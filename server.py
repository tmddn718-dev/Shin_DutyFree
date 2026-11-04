#!/usr/bin/env python3
"""
회원가입 프로토타입 백엔드 (Python 표준 라이브러리 + SQLite, 설치 필요 없음)

실행:  python3 server.py            → http://localhost:8000
옵션:  python3 server.py --port 8080 --db signup.db

제공하는 것
  GET  /                           index.html
  GET  /api/health                 서버 동작 확인
  GET  /api/users/check-id         아이디 중복확인      ?userId=...
  GET  /api/users/check-nickname   닉네임 중복확인      ?nickname=...
  GET  /api/users/check-referrer   추천인 아이디 확인   ?userId=...
  POST /api/email/check            이메일 가입 가능 여부 {email, phone}
  POST /api/signup                 회원가입 + 약관 동의 저장
  POST /api/consents               가입 직후 동의 내용 수정 (가입 응답의 consentToken 필요, 30분 유효)

간편가입 (OAuth, 가입만 한다. 로그인·세션은 아직 없음)
  GET  /api/auth/providers         사용할 수 있는 제공자와 모드(live | demo)
  GET  /api/auth/{제공자}/start     제공자 로그인 화면으로 보냄 (state 를 쿠키와 서버에 저장)
  GET  /api/auth/{제공자}/callback  코드 → 토큰 → 프로필, 가입용 티켓을 만들어 /#social=티켓 으로 돌려보냄
  POST /api/auth/ticket            {ticket} → 프로필(이메일·닉네임). 가입할 때 signup 에 socialTicket 으로 보냄
  키는 .env 의 OAUTH_<제공자>_CLIENT_ID / _CLIENT_SECRET 에서 읽는다. 키가 없으면 시연 모드로 가짜 프로필을 쓴다.

탈퇴한 이메일로 다시 가입할 때
  본인인증한 휴대폰이 탈퇴 회원의 휴대폰과 같고 탈퇴 후 30일 이내면 → 복귀 회원 (기존 가입일 유지)
  30일이 지났거나 휴대폰이 다르면                                   → 신규 회원

실제 본인인증·이메일 소유 확인은 하지 않는다. 시연·검증용 서버다.
"""
import argparse
import hashlib
import json
import os
import re
import secrets
import sqlite3
import threading
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

ROOT = Path(__file__).resolve().parent
MAX_BODY = 16 * 1024  # 요청 본문 최대 16KB
REJOIN_DAYS = 30  # 탈퇴 후 이 기간 안에 돌아오면 복귀 회원
CONSENT_TOKEN_TTL = timedelta(minutes=30)  # 가입 직후 동의 수정 가능 시간

# ---------- 입력 규칙 (index.html 의 프런트 규칙과 같게 유지) ----------
ID_RE = re.compile(r"^(?=.*[a-z])[a-z0-9]{6,20}$")
NICK_RE = re.compile(r"^[가-힣A-Za-z0-9]{2,10}$")
EMAIL_RE = re.compile(r"^[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)+$")
PHONE_RE = re.compile(r"^01[0-9]-?\d{3,4}-?\d{4}$")
ZIP_RE = re.compile(r"^\d{5}$")
REQUIRED_CONSENTS = ("terms", "privacy", "age")
SERVICES = ("이마트", "신세계백화점", "신백멤버스", "신세계아울렛", "시코르",
            "이마트에브리데이", "신세계까사", "스타필드", "이마트24")
CHANNELS = ("이메일", "문자", "우편", "전화")

ID_RULE_MSG = "아이디는 영문 소문자를 포함해 영문, 숫자 6~20자로 입력해 주세요."
NICK_RULE_MSG = "닉네임은 한글, 영문, 숫자 2~10자로 입력해 주세요."


def password_ok(pw: str) -> bool:
    if not isinstance(pw, str) or not (8 <= len(pw) <= 20) or re.search(r"\s", pw):
        return False
    return all(re.search(p, pw) for p in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9\s]"))


def hash_secret(value: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(value.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${digest.hex()}"


def token_digest(token: str) -> str:
    # 토큰은 충분히 긴 난수라서 빠른 해시로도 안전하게 찾을 수 있다
    return hashlib.sha256(token.encode()).hexdigest()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def now() -> str:
    return utcnow().isoformat(timespec="seconds")


def normalize_phone(phone: str) -> str:
    """'01012345678', '010-1234-5678' 을 모두 '010-1234-5678' 로 맞춘다."""
    d = re.sub(r"\D", "", phone or "")
    if len(d) == 11:
        return f"{d[:3]}-{d[3:7]}-{d[7:]}"
    if len(d) == 10:
        return f"{d[:3]}-{d[3:6]}-{d[6:]}"
    return phone or ""


def normalize_email(email: str) -> str:
    return email.strip().lower()


# ---------- 간편가입 (OAuth 2.0 인가 코드 방식) ----------
def load_dotenv(path: Path) -> None:
    """KEY=VALUE 형식의 .env 를 읽어 환경변수로 넣는다 (이미 있는 값은 그대로 둔다)."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def _kakao_profile(j: dict) -> dict:
    acc = j.get("kakao_account") or {}
    return {"subject": str(j["id"]), "email": acc.get("email"),
            "emailVerified": bool(acc.get("is_email_verified")),
            "nickname": (acc.get("profile") or {}).get("nickname") or (j.get("properties") or {}).get("nickname")}


def _naver_profile(j: dict) -> dict:
    r = j.get("response") or {}
    # 네이버는 로그인할 때 이메일을 확인하므로 받은 이메일은 확인된 것으로 본다
    return {"subject": str(r["id"]), "email": r.get("email"), "emailVerified": bool(r.get("email")),
            "nickname": r.get("nickname") or r.get("name")}


def _google_profile(j: dict) -> dict:
    return {"subject": str(j["sub"]), "email": j.get("email"), "emailVerified": bool(j.get("email_verified")),
            "nickname": j.get("name")}


# 제공자를 늘리려면 여기에 한 줄 추가하고 .env 에 키를 넣는다
OAUTH_PROVIDERS = {
    "kakao": {
        "name": "카카오",
        "authorize_url": "https://kauth.kakao.com/oauth/authorize",
        "token_url": "https://kauth.kakao.com/oauth/token",
        "profile_url": "https://kapi.kakao.com/v2/user/me",
        "scope": "account_email profile_nickname",
        "parse": _kakao_profile,
    },
    "naver": {
        "name": "네이버",
        "authorize_url": "https://nid.naver.com/oauth2.0/authorize",
        "token_url": "https://nid.naver.com/oauth2.0/token",
        "profile_url": "https://openapi.naver.com/v1/nid/me",
        "scope": "",
        "token_needs_state": True,
        "parse": _naver_profile,
    },
    "google": {
        "name": "구글",
        "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "profile_url": "https://openidconnect.googleapis.com/v1/userinfo",
        "scope": "openid email profile",
        "parse": _google_profile,
    },
}
OAUTH_STATE_TTL = timedelta(minutes=10)    # 제공자 로그인 화면에 다녀오는 시간
SOCIAL_TICKET_TTL = timedelta(minutes=30)  # 콜백 뒤 가입을 마치는 시간


def oauth_keys(provider: str) -> tuple[str, str]:
    p = provider.upper()
    return os.environ.get(f"OAUTH_{p}_CLIENT_ID", ""), os.environ.get(f"OAUTH_{p}_CLIENT_SECRET", "")


def oauth_mode(provider: str) -> str:
    return "live" if oauth_keys(provider)[0] else "demo"


def http_json(url: str, data: dict | None = None, token: str | None = None) -> dict:
    """제공자 API 호출. data 가 있으면 폼으로 POST, token 이 있으면 Bearer 로 보낸다."""
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = urlencode(data).encode() if data is not None else None
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded;charset=utf-8"
    req = urllib.request.Request(url, data=body, headers=headers)
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def fetch_social_profile(provider: str, code: str, state: str, redirect_uri: str) -> dict:
    cfg = OAUTH_PROVIDERS[provider]
    client_id, client_secret = oauth_keys(provider)
    if not client_id:
        # 시연 모드: 실제 제공자 없이 가짜 프로필을 만든다
        tag = secrets.token_hex(3)
        return {"subject": f"demo-{tag}", "email": f"{provider}{tag}@example.com",
                "emailVerified": True, "nickname": f"{cfg['name']}{tag[:4]}"}
    form = {"grant_type": "authorization_code", "client_id": client_id,
            "redirect_uri": redirect_uri, "code": code}
    if client_secret:
        form["client_secret"] = client_secret
    if cfg.get("token_needs_state"):
        form["state"] = state
    token = http_json(cfg["token_url"], data=form).get("access_token")
    if not token:
        raise ValueError("no access_token")
    return cfg["parse"](http_json(cfg["profile_url"], token=token))


# ---------- DB ----------
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id         TEXT NOT NULL UNIQUE,
  email           TEXT NOT NULL UNIQUE,
  password_hash   TEXT NOT NULL,
  name            TEXT NOT NULL,
  phone           TEXT NOT NULL,
  zipcode         TEXT,
  address1        TEXT,
  address2        TEXT,
  created_at      TEXT NOT NULL
);
-- 아이디·닉네임으로 쓸 수 없는 예약어
CREATE TABLE IF NOT EXISTS reserved_ids (
  user_id TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS reserved_nicknames (
  nickname TEXT PRIMARY KEY COLLATE NOCASE
);
-- 이전 가입 이력: withdrawn = 탈퇴, blocked = 가입 제한
CREATE TABLE IF NOT EXISTS email_history (
  email      TEXT PRIMARY KEY,
  status     TEXT NOT NULL CHECK (status IN ('withdrawn', 'blocked')),
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS consents (
  user_pk        INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  terms          INTEGER NOT NULL,
  privacy        INTEGER NOT NULL,
  age            INTEGER NOT NULL,
  services       TEXT NOT NULL,   -- JSON: {"서비스명": true/false}
  marketing      TEXT NOT NULL,   -- JSON: {"point": {...}, "duty": {...}, "night": bool}
  token_hash     TEXT NOT NULL UNIQUE, -- 가입 직후 동의 수정용 토큰의 SHA-256
  agreed_at      TEXT NOT NULL,
  updated_at     TEXT NOT NULL
);
-- 간편가입으로 연결된 제공자 계정 (제공자 + 제공자 쪽 회원번호가 한 사람)
CREATE TABLE IF NOT EXISTS social_accounts (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_pk    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider   TEXT NOT NULL,
  subject    TEXT NOT NULL,
  email      TEXT,
  linked_at  TEXT NOT NULL,
  UNIQUE (provider, subject)
);
-- 콜백에서 받은 프로필을 가입이 끝날 때까지 잠시 보관 (토큰은 해시만 저장)
CREATE TABLE IF NOT EXISTS social_tickets (
  token_hash     TEXT PRIMARY KEY,
  provider       TEXT NOT NULL,
  subject        TEXT NOT NULL,
  email          TEXT,
  email_verified INTEGER NOT NULL,
  nickname       TEXT,
  expires_at     TEXT NOT NULL,
  used_at        TEXT
);
"""

# 처음 만든 뒤 추가한 컬럼. 예전 signup.db 도 그대로 쓸 수 있게 없으면 붙인다.
ADDED_COLUMNS = {
    "users": {
        "nickname": "TEXT",
        "member_type": "TEXT NOT NULL DEFAULT 'new'",  # new | returning
        "first_joined_at": "TEXT",                     # 복귀 회원이면 탈퇴 전 가입일
        "referrer_pk": "INTEGER REFERENCES users(id)",
    },
    "email_history": {
        "phone": "TEXT",           # 탈퇴 회원의 본인인증 휴대폰
        "withdrawn_at": "TEXT",
        "prev_joined_at": "TEXT",  # 탈퇴 전 가입일
    },
    "consents": {
        "token_expires_at": "TEXT",
    },
}
INDEXES = """
CREATE UNIQUE INDEX IF NOT EXISTS users_nickname ON users(nickname COLLATE NOCASE);
"""

# 시연용 초기 데이터
DEMO_PHONE = "010-1234-5678"  # index.html 의 demoVerified 휴대폰과 같다
SEED_RESERVED = ["admin", "shinsegae", "test1234", "gudals4360"]
SEED_RESERVED_NICKS = ["관리자", "운영자", "admin", "신세계"]
SEED_REFERRER = ("friend1234", "friend@example.com", "친구", "010-9876-5432")


def seed_history():
    """시연용 탈퇴·제한 이메일. 날짜가 실행 시점 기준이라 서버를 켤 때마다 다시 넣는다."""
    t = utcnow()
    return [
        # (email, status, phone, withdrawn_at, prev_joined_at)
        ("rejoin@example.com", "withdrawn", DEMO_PHONE, t - timedelta(days=10), "2024-03-15T00:00:00+00:00"),
        ("old@example.com", "withdrawn", DEMO_PHONE, t - timedelta(days=45), "2023-07-01T00:00:00+00:00"),
        ("blocked@example.com", "blocked", None, None, None),
    ]


class Store:
    def __init__(self, path: Path):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.lock = threading.Lock()
        with self.lock, self.conn:
            self.conn.executescript(SCHEMA)
            self._migrate()
            self.conn.executescript(INDEXES)
            self._seed()

    def _migrate(self):
        for table, cols in ADDED_COLUMNS.items():
            have = {r["name"] for r in self.conn.execute(f"PRAGMA table_info({table})")}
            for col, ddl in cols.items():
                if col not in have:
                    self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")

    def _seed(self):
        self.conn.executemany("INSERT OR IGNORE INTO reserved_ids(user_id) VALUES (?)",
                              [(i,) for i in SEED_RESERVED])
        self.conn.executemany("INSERT OR IGNORE INTO reserved_nicknames(nickname) VALUES (?)",
                              [(n,) for n in SEED_RESERVED_NICKS])
        uid, email, nick, phone = SEED_REFERRER
        # 추천인 시연용 회원 (비밀번호는 아무도 모르는 난수)
        self.conn.execute(
            """INSERT OR IGNORE INTO users(user_id, email, password_hash, name, phone, nickname,
                                           member_type, first_joined_at, created_at)
               VALUES (?, ?, ?, '친구', ?, ?, 'new', ?, ?)""",
            (uid, email, hash_secret(secrets.token_hex(16)), phone, nick, now(), now()),
        )
        for email, status, phone, withdrawn_at, prev in seed_history():
            self.conn.execute(
                """INSERT INTO email_history(email, status, phone, withdrawn_at, prev_joined_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(email) DO UPDATE SET status=excluded.status, phone=excluded.phone,
                     withdrawn_at=excluded.withdrawn_at, prev_joined_at=excluded.prev_joined_at,
                     updated_at=excluded.updated_at""",
                (email, status, phone,
                 withdrawn_at.isoformat(timespec="seconds") if withdrawn_at else None, prev, now()),
            )

    # --- 조회 ---
    def _id_taken(self, user_id: str) -> bool:
        return self.conn.execute(
            "SELECT 1 FROM users WHERE user_id = ? UNION SELECT 1 FROM reserved_ids WHERE user_id = ?",
            (user_id, user_id),
        ).fetchone() is not None

    def _nickname_taken(self, nickname: str) -> bool:
        return self.conn.execute(
            """SELECT 1 FROM users WHERE nickname = ? COLLATE NOCASE
               UNION SELECT 1 FROM reserved_nicknames WHERE nickname = ? COLLATE NOCASE""",
            (nickname, nickname),
        ).fetchone() is not None

    def id_available(self, user_id: str) -> bool:
        with self.lock:
            return not self._id_taken(user_id)

    def nickname_available(self, nickname: str) -> bool:
        with self.lock:
            return not self._nickname_taken(nickname)

    def referrer_exists(self, user_id: str) -> bool:
        with self.lock:
            return self.conn.execute("SELECT 1 FROM users WHERE user_id = ?", (user_id,)).fetchone() is not None

    @staticmethod
    def _rejoin(row, phone: str) -> dict:
        """탈퇴 이력 + 본인인증 휴대폰으로 복귀/신규를 정한다.
        휴대폰이 같아야 같은 사람으로 보고, 그때만 남은 기간·만료 사유를 알려 준다."""
        same_person = bool(phone) and row["phone"] == normalize_phone(phone)
        if not same_person or not row["withdrawn_at"]:
            return {"status": "rejoin_new"}
        elapsed = utcnow() - datetime.fromisoformat(row["withdrawn_at"])
        if elapsed <= timedelta(days=REJOIN_DAYS):
            return {"status": "returning", "daysLeft": REJOIN_DAYS - elapsed.days,
                    "firstJoinedAt": row["prev_joined_at"]}
        return {"status": "rejoin_new", "reason": "expired"}

    def email_status(self, email: str, phone: str) -> dict:
        """status: available | returning | rejoin_new | unavailable
        이미 가입된 이메일과 가입 제한 이메일은 같은 값(unavailable)으로 돌려줘 사유를 드러내지 않는다."""
        email = normalize_email(email)
        with self.lock:
            if self.conn.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
                return {"status": "unavailable"}
            row = self.conn.execute("SELECT * FROM email_history WHERE email = ?", (email,)).fetchone()
        if row is None:
            return {"status": "available"}
        if row["status"] == "blocked":
            return {"status": "unavailable"}
        return self._rejoin(row, phone)

    # --- 간편가입 ---
    def create_social_ticket(self, provider: str, profile: dict) -> str | None:
        """이미 연결된 계정이면 None (가입만 다루므로 로그인으로 넘기지 않는다)."""
        token = secrets.token_urlsafe(24)
        email = normalize_email(profile["email"]) if profile.get("email") else None
        with self.lock, self.conn:
            if self.conn.execute("SELECT 1 FROM social_accounts WHERE provider = ? AND subject = ?",
                                 (provider, profile["subject"])).fetchone():
                return None
            # 오래된 티켓은 여기서 같이 정리한다
            self.conn.execute("DELETE FROM social_tickets WHERE expires_at < ?", (now(),))
            self.conn.execute(
                """INSERT INTO social_tickets(token_hash, provider, subject, email, email_verified, nickname, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (token_digest(token), provider, profile["subject"], email, int(bool(profile.get("emailVerified"))),
                 profile.get("nickname"), (utcnow() + SOCIAL_TICKET_TTL).isoformat(timespec="seconds")),
            )
        return token

    def _ticket_row(self, ticket: str):
        row = self.conn.execute("SELECT * FROM social_tickets WHERE token_hash = ?", (token_digest(ticket),)).fetchone()
        if row is None or row["used_at"] or datetime.fromisoformat(row["expires_at"]) < utcnow():
            raise HttpError(HTTPStatus.UNAUTHORIZED, "social_ticket_invalid",
                            "간편가입 정보가 만료됐어요. 처음부터 다시 진행해 주세요.")
        return row

    def social_ticket(self, ticket: str) -> dict:
        with self.lock:
            row = self._ticket_row(ticket)
        return {"provider": row["provider"], "providerName": OAUTH_PROVIDERS[row["provider"]]["name"],
                "email": row["email"], "emailVerified": bool(row["email_verified"]), "nickname": row["nickname"]}

    def _new_social_user_id(self, provider: str) -> str:
        # 간편가입 회원도 내부 아이디는 필요하다. 사용자가 쓰지 않는 값으로 만든다
        while True:
            user_id = f"{provider}{secrets.token_hex(5)}"
            if not self._id_taken(user_id):
                return user_id

    # --- 가입 ---
    def create_user(self, data: dict, consents: dict) -> dict:
        token = secrets.token_urlsafe(24)
        email = data["email"]
        addr = data.get("address") or {}
        with self.lock, self.conn:
            social = None
            if data.get("socialTicket"):
                # 간편가입: 아이디·비밀번호 없이 티켓의 제공자 계정을 연결한다
                social = self._ticket_row(data["socialTicket"])
                if self.conn.execute("SELECT 1 FROM social_accounts WHERE provider = ? AND subject = ?",
                                     (social["provider"], social["subject"])).fetchone():
                    raise Conflict("social_already_linked", "이미 가입된 간편가입 계정이에요.")
                data = {**data, "userId": self._new_social_user_id(social["provider"])}
            # 동시에 같은 아이디/닉네임/이메일로 가입하는 경우를 막기 위해 트랜잭션 안에서 다시 확인
            if self._id_taken(data["userId"]):
                raise Conflict("id_taken", "이미 사용 중인 아이디예요. 다른 아이디로 다시 확인해 주세요.")
            if self._nickname_taken(data["nickname"]):
                raise Conflict("nickname_taken", "이미 사용 중인 닉네임이에요. 다른 닉네임으로 다시 확인해 주세요.")
            if self.conn.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
                raise Conflict("email_unavailable", "현재 이 이메일로 가입할 수 없어요. 다른 이메일을 사용해 주세요.")
            history = self.conn.execute("SELECT * FROM email_history WHERE email = ?", (email,)).fetchone()
            if history is not None and history["status"] == "blocked":
                raise Conflict("email_unavailable", "현재 이 이메일로 가입할 수 없어요. 다른 이메일을 사용해 주세요.")

            referrer_pk = None
            if data.get("referrer"):
                ref = self.conn.execute("SELECT id FROM users WHERE user_id = ?", (data["referrer"],)).fetchone()
                if ref is None:
                    raise HttpError(HTTPStatus.BAD_REQUEST, "referrer_not_found",
                                    "추천인 아이디를 찾을 수 없어요. 다시 확인해 주세요.")
                referrer_pk = ref["id"]

            # 복귀 여부는 화면에서 받은 값이 아니라 여기서 다시 계산한다
            rejoin = self._rejoin(history, data["phone"]) if history is not None else {"status": "new"}
            returning = rejoin["status"] == "returning"
            member_type = "returning" if returning else "new"
            first_joined_at = rejoin["firstJoinedAt"] if returning else now()

            cur = self.conn.execute(
                """INSERT INTO users(user_id, email, password_hash, name, phone, nickname,
                                     zipcode, address1, address2, member_type, first_joined_at,
                                     referrer_pk, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    # 간편가입 회원은 비밀번호가 없다 ("!" 는 어떤 비밀번호와도 맞지 않는 값)
                    data["userId"], email, "!" if social else hash_secret(data["password"]),
                    data["name"], data["phone"], data["nickname"],
                    addr.get("zipcode"), addr.get("address1"), addr.get("address2"),
                    member_type, first_joined_at, referrer_pk, now(),
                ),
            )
            user_pk = cur.lastrowid
            # 다시 회원이 되었으므로 탈퇴 이력은 지운다
            self.conn.execute("DELETE FROM email_history WHERE email = ?", (email,))
            self._write_consents(user_pk, consents, token_digest(token), insert=True)
            if social:
                self.conn.execute(
                    "INSERT INTO social_accounts(user_pk, provider, subject, email, linked_at) VALUES (?, ?, ?, ?, ?)",
                    (user_pk, social["provider"], social["subject"], social["email"], now()),
                )
                self.conn.execute("UPDATE social_tickets SET used_at = ? WHERE token_hash = ?",
                                  (now(), social["token_hash"]))
        return {"userId": data["userId"], "nickname": data["nickname"], "consentToken": token,
                "memberType": member_type, "firstJoinedAt": first_joined_at,
                "socialProvider": social["provider"] if social else None}

    def update_consents(self, token: str, consents: dict) -> None:
        with self.lock, self.conn:
            row = self.conn.execute(
                "SELECT user_pk, token_expires_at FROM consents WHERE token_hash = ?", (token_digest(token),)
            ).fetchone()
            if row is None:
                raise HttpError(HTTPStatus.UNAUTHORIZED, "invalid_token", "동의 내용을 수정할 수 없어요. 다시 시도해 주세요.")
            if not row["token_expires_at"] or datetime.fromisoformat(row["token_expires_at"]) < utcnow():
                raise HttpError(HTTPStatus.UNAUTHORIZED, "token_expired",
                                "가입 직후 수정할 수 있는 시간이 지났어요. 로그인 후 내 정보에서 바꿔 주세요.")
            self._write_consents(row["user_pk"], consents, None, insert=False)

    def _write_consents(self, user_pk: int, c: dict, token_hash: str | None, insert: bool) -> None:
        req = c["required"]
        values = (
            int(req["terms"]), int(req["privacy"]), int(req["age"]),
            json.dumps(c["services"], ensure_ascii=False),
            json.dumps(c["marketing"], ensure_ascii=False),
        )
        if insert:
            expires = (utcnow() + CONSENT_TOKEN_TTL).isoformat(timespec="seconds")
            self.conn.execute(
                """INSERT INTO consents(user_pk, terms, privacy, age, services, marketing,
                                        token_hash, token_expires_at, agreed_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (user_pk, *values, token_hash, expires, now(), now()),
            )
        else:
            self.conn.execute(
                """UPDATE consents SET terms=?, privacy=?, age=?, services=?, marketing=?, updated_at=?
                   WHERE user_pk=?""",
                (*values, now(), user_pk),
            )


# ---------- 오류 ----------
class HttpError(Exception):
    def __init__(self, status: HTTPStatus, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


class Conflict(HttpError):
    def __init__(self, code: str, message: str):
        super().__init__(HTTPStatus.CONFLICT, code, message)


def bad_request(message: str) -> HttpError:
    return HttpError(HTTPStatus.BAD_REQUEST, "invalid_input", message)


# ---------- 입력 검증 ----------
def validate_signup(body: dict) -> dict:
    """검증하면서 저장할 형태로 정리한 새 dict 를 돌려준다.
    socialTicket 이 있으면 간편가입이라 아이디·비밀번호를 받지 않는다 (티켓은 저장할 때 확인)."""
    social_ticket = body.get("socialTicket") or None
    if social_ticket is not None and not isinstance(social_ticket, str):
        raise HttpError(HTTPStatus.UNAUTHORIZED, "social_ticket_invalid",
                        "간편가입 정보가 만료됐어요. 처음부터 다시 진행해 주세요.")
    user_id = "" if social_ticket else body.get("userId", "")
    if not social_ticket:
        if not isinstance(user_id, str) or not ID_RE.match(user_id):
            raise bad_request(ID_RULE_MSG)
        if not password_ok(body.get("password", "")):
            raise bad_request("비밀번호 규칙을 확인해 주세요.")
    nickname = body.get("nickname", "")
    if not isinstance(nickname, str) or not NICK_RE.match(nickname.strip()):
        raise bad_request(NICK_RULE_MSG)
    name = body.get("name", "")
    if not isinstance(name, str) or not (1 <= len(name.strip()) <= 30):
        raise bad_request("이름을 확인해 주세요.")
    phone = body.get("phone", "")
    if not isinstance(phone, str) or not PHONE_RE.match(phone.strip()):
        raise bad_request("휴대폰 번호를 확인해 주세요.")
    email = body.get("email", "")
    if not isinstance(email, str) or len(email) > 254 or not EMAIL_RE.match(normalize_email(email)):
        raise bad_request("이메일 형식을 확인해 주세요.")

    addr = body.get("address")
    clean_addr = None
    if addr is not None:
        if not isinstance(addr, dict):
            raise bad_request("주소를 확인해 주세요.")
        zipcode, address1, address2 = addr.get("zipcode"), addr.get("address1"), addr.get("address2", "")
        if not isinstance(zipcode, str) or not ZIP_RE.match(zipcode) \
           or not isinstance(address1, str) or not address1.strip() \
           or not isinstance(address2, str):
            raise bad_request("주소를 확인해 주세요.")
        if len(address1) > 200 or len(address2) > 200:
            raise bad_request("주소가 너무 길어요.")
        clean_addr = {"zipcode": zipcode, "address1": address1.strip(), "address2": address2.strip()}

    referrer = body.get("referrer") or None
    if referrer is not None:
        if not isinstance(referrer, str) or not ID_RE.match(referrer.strip().lower()):
            raise HttpError(HTTPStatus.BAD_REQUEST, "referrer_not_found", "추천인 아이디를 확인해 주세요.")
        referrer = referrer.strip().lower()
        if referrer == user_id:
            raise HttpError(HTTPStatus.BAD_REQUEST, "referrer_self", "본인 아이디는 추천인으로 입력할 수 없어요.")

    return {
        "userId": user_id, "password": body.get("password"), "socialTicket": social_ticket,
        "nickname": nickname.strip(),
        "name": name.strip(), "phone": normalize_phone(phone.strip()), "email": normalize_email(email),
        "address": clean_addr, "referrer": referrer,
    }


def validate_consents(c) -> dict:
    if not isinstance(c, dict):
        raise bad_request("약관 동의 정보가 없어요.")
    req = c.get("required")
    if not isinstance(req, dict) or not all(req.get(k) is True for k in REQUIRED_CONSENTS):
        raise HttpError(HTTPStatus.BAD_REQUEST, "consent_required", "필수 약관에 모두 동의해 주세요.")
    services = c.get("services") or {}
    marketing = c.get("marketing") or {}
    if not isinstance(services, dict) or not set(services) <= set(SERVICES) \
       or not all(isinstance(v, bool) for v in services.values()):
        raise bad_request("서비스 동의 정보가 올바르지 않아요.")
    if not isinstance(marketing, dict) or \
       not all(isinstance(marketing.get(g), (dict, type(None))) for g in ("point", "duty")):
        raise bad_request("마케팅 동의 정보가 올바르지 않아요.")
    clean_mk = {
        g: {ch: bool((marketing.get(g) or {}).get(ch)) for ch in CHANNELS} for g in ("point", "duty")
    }
    clean_mk["night"] = bool(marketing.get("night"))
    return {"required": {k: True for k in REQUIRED_CONSENTS},
            "services": {s: bool(services.get(s)) for s in SERVICES},
            "marketing": clean_mk}


# ---------- HTTP ----------
class Handler(BaseHTTPRequestHandler):
    store: Store = None  # main 에서 주입
    base_url = ""        # main 에서 주입. 제공자에 등록한 redirect URI 의 앞부분
    server_version = "SignupPrototype/1.0"
    # OAuth state: 제공자에 다녀오는 동안만 메모리에 둔다 {state: (제공자, 만료 시각)}
    oauth_states: dict = {}
    oauth_lock = threading.Lock()

    def log_message(self, fmt, *args):  # 비밀번호 등이 로그에 남지 않도록 경로만 기록
        print(f"{self.command} {urlparse(self.path).path} -> {args[1] if len(args) > 1 else ''}", flush=True)

    def _send(self, status, body: bytes, ctype: str, headers: dict | None = None):
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status, payload):
        self._send(status, json.dumps(payload, ensure_ascii=False).encode(), "application/json; charset=utf-8")

    def _redirect(self, location: str, cookie: str | None = None):
        self._send(HTTPStatus.FOUND, b"", "text/plain; charset=utf-8",
                   {"Location": location, **({"Set-Cookie": cookie} if cookie else {})})

    def _cookie(self, name: str) -> str:
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return ""

    # --- 간편가입 ---
    def _oauth_start(self, provider: str):
        cfg = OAUTH_PROVIDERS[provider]
        client_id = oauth_keys(provider)[0]
        base = urlparse(self.base_url)
        if client_id and self.headers.get("Host") != base.netloc:
            # state 쿠키가 콜백 주소와 같은 호스트에 남도록 등록한 주소로 다시 시작한다
            return self._redirect(f"{self.base_url}/api/auth/{provider}/start")
        state = secrets.token_urlsafe(16)
        with self.oauth_lock:
            t = utcnow()
            for s in [s for s, (_, exp) in self.oauth_states.items() if exp < t]:
                del self.oauth_states[s]
            self.oauth_states[state] = (provider, t + OAUTH_STATE_TTL)
        cookie = (f"oauth_state={state}; Path=/api/auth; Max-Age={int(OAUTH_STATE_TTL.total_seconds())}; "
                  "HttpOnly; SameSite=Lax")
        redirect_uri = f"{self.base_url}/api/auth/{provider}/callback"
        if not client_id:
            # 시연 모드: 제공자 화면 대신 바로 콜백으로
            return self._redirect(f"/api/auth/{provider}/callback?" + urlencode({"code": "demo", "state": state}), cookie)
        params = {"response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri, "state": state}
        if cfg["scope"]:
            params["scope"] = cfg["scope"]
        self._redirect(f"{cfg['authorize_url']}?{urlencode(params)}", cookie)

    def _oauth_callback(self, provider: str, query: dict):
        arg = lambda k: (query.get(k) or [""])[0]
        clear = "oauth_state=; Path=/api/auth; Max-Age=0; HttpOnly; SameSite=Lax"
        fail = lambda reason: self._redirect(f"/#social_error={reason}", clear)
        state = arg("state")
        with self.oauth_lock:
            saved = self.oauth_states.pop(state, None)
        # state 가 서버에 있고, 이 브라우저 쿠키와 같고, 같은 제공자여야 한다 (다른 사람이 만든 콜백 차단)
        if not state or saved is None or saved[0] != provider or saved[1] < utcnow() \
           or not secrets.compare_digest(self._cookie("oauth_state"), state):
            return fail("state")
        if arg("error"):
            return fail("denied")  # 사용자가 제공자 화면에서 취소
        try:
            profile = fetch_social_profile(provider, arg("code"), state,
                                           f"{self.base_url}/api/auth/{provider}/callback")
        except (urllib.error.URLError, ValueError, KeyError, TimeoutError) as e:
            print("oauth error:", provider, repr(e), flush=True)
            return fail("provider")
        ticket = self.store.create_social_ticket(provider, profile)
        if ticket is None:
            return fail("already")
        # 티켓은 # 뒤에 붙여 서버 로그·Referer 로 새지 않게 한다
        self._redirect(f"/#social={ticket}", clear)

    def _read_json(self) -> dict:
        if "application/json" not in (self.headers.get("Content-Type") or ""):
            raise HttpError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "invalid_content_type", "JSON으로 보내 주세요.")
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0:
            # 음수를 그대로 read() 에 넘기면 연결이 끊길 때까지 기다리게 된다
            self.close_connection = True
            raise bad_request("요청 형식이 올바르지 않아요.")
        if length > MAX_BODY:
            self.close_connection = True
            raise HttpError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "too_large", "요청이 너무 커요.")
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:  # JSON 오류와 UTF-8 이 아닌 본문 모두
            raise bad_request("요청 형식이 올바르지 않아요.")
        if not isinstance(data, dict):
            raise bad_request("요청 형식이 올바르지 않아요.")
        return data

    def _handle(self, fn):
        try:
            fn()
        except HttpError as e:
            self._json(e.status, {"error": e.code, "message": e.message})
        except Exception as e:  # 예상하지 못한 오류는 내용을 숨긴다
            print("server error:", repr(e), flush=True)
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR,
                       {"error": "server_error", "message": "잠시 후 다시 시도해 주세요."})

    def do_GET(self):
        self._handle(self._get)

    def do_POST(self):
        self._handle(self._post)

    def _get(self):
        url = urlparse(self.path)
        query = parse_qs(url.query)
        arg = lambda k: (query.get(k) or [""])[0]
        if url.path in ("/", "/index.html"):
            # index.html 만 제공한다 (DB 파일 등 다른 파일은 노출하지 않음)
            self._send(HTTPStatus.OK, (ROOT / "index.html").read_bytes(), "text/html; charset=utf-8")
        elif url.path == "/api/health":
            self._json(HTTPStatus.OK, {"ok": True})
        elif url.path == "/api/users/check-id":
            user_id = arg("userId")
            if not ID_RE.match(user_id):
                raise bad_request(ID_RULE_MSG)
            self._json(HTTPStatus.OK, {"available": self.store.id_available(user_id)})
        elif url.path == "/api/users/check-nickname":
            nickname = arg("nickname").strip()
            if not NICK_RE.match(nickname):
                raise bad_request(NICK_RULE_MSG)
            self._json(HTTPStatus.OK, {"available": self.store.nickname_available(nickname)})
        elif url.path == "/api/auth/providers":
            self._json(HTTPStatus.OK, {"providers": [
                {"id": p, "name": cfg["name"], "mode": oauth_mode(p)} for p, cfg in OAUTH_PROVIDERS.items()
            ]})
        elif (m := re.fullmatch(r"/api/auth/([a-z]+)/(start|callback)", url.path)) and m[1] in OAUTH_PROVIDERS:
            if m[2] == "start":
                self._oauth_start(m[1])
            else:
                self._oauth_callback(m[1], query)
        elif url.path == "/api/users/check-referrer":
            user_id = arg("userId").strip().lower()
            if not ID_RE.match(user_id):
                raise bad_request("추천인 아이디를 확인해 주세요.")
            self._json(HTTPStatus.OK, {"exists": self.store.referrer_exists(user_id)})
        else:
            raise HttpError(HTTPStatus.NOT_FOUND, "not_found", "찾을 수 없어요.")

    def _post(self):
        path = urlparse(self.path).path
        if path == "/api/email/check":
            body = self._read_json()
            email, phone = body.get("email", ""), body.get("phone", "")
            if not isinstance(email, str) or not EMAIL_RE.match(normalize_email(email)):
                raise bad_request("이메일 형식을 확인해 주세요.")
            if not isinstance(phone, str):
                raise bad_request("휴대폰 번호를 확인해 주세요.")
            self._json(HTTPStatus.OK, self.store.email_status(email, phone))
        elif path == "/api/auth/ticket":
            ticket = self._read_json().get("ticket")
            if not isinstance(ticket, str) or not ticket:
                raise HttpError(HTTPStatus.UNAUTHORIZED, "social_ticket_invalid",
                                "간편가입 정보가 만료됐어요. 처음부터 다시 진행해 주세요.")
            self._json(HTTPStatus.OK, self.store.social_ticket(ticket))
        elif path == "/api/signup":
            body = self._read_json()
            data = validate_signup(body)
            consents = validate_consents(body.get("consents"))
            self._json(HTTPStatus.CREATED, {"ok": True, **self.store.create_user(data, consents)})
        elif path == "/api/consents":
            body = self._read_json()
            token = body.get("consentToken")
            if not isinstance(token, str) or not token:
                raise HttpError(HTTPStatus.UNAUTHORIZED, "invalid_token", "동의 내용을 수정할 수 없어요.")
            self.store.update_consents(token, validate_consents(body.get("consents")))
            self._json(HTTPStatus.OK, {"ok": True})
        else:
            raise HttpError(HTTPStatus.NOT_FOUND, "not_found", "찾을 수 없어요.")


def main():
    parser = argparse.ArgumentParser(description="회원가입 프로토타입 백엔드")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--db", default=str(ROOT / "signup.db"))
    args = parser.parse_args()

    load_dotenv(ROOT / ".env")
    # 제공자 개발자 센터에 등록하는 redirect URI = PUBLIC_BASE_URL + /api/auth/{제공자}/callback
    Handler.base_url = os.environ.get("PUBLIC_BASE_URL", f"http://localhost:{args.port}").rstrip("/")
    Handler.store = Store(Path(args.db))
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"http://{args.host}:{args.port} 에서 실행 중 (DB: {args.db}) - 끝내려면 Ctrl+C", flush=True)
    print("간편가입: " + ", ".join(f"{cfg['name']}={oauth_mode(p)}" for p, cfg in OAUTH_PROVIDERS.items()), flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
