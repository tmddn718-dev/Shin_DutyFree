// Supabase Edge Function: 회원가입 API (이전 server.py 와 같은 요청/응답)
// 배포: supabase functions deploy api   (config.toml 에서 verify_jwt = false)
// 주소: https://<프로젝트>.supabase.co/functions/v1/api/<경로>
import { createClient } from "npm:@supabase/supabase-js@2.45.4";


// ===== 아래는 rules.ts 와 같은 내용 (대시보드에 한 파일로 붙여 넣기 위해 합침) =====
// 입력 규칙과 검증. Deno/Node 어디서든 도는 순수 코드 (index.ts 의 DB 호출과 분리)
// index.html 의 프런트 규칙, 이전 server.py 와 같게 유지한다.

const ID_RE = /^(?=.*[a-z])[a-z0-9]{6,20}$/;
const NICK_RE = /^[가-힣A-Za-z0-9]{2,10}$/;
const EMAIL_RE = /^[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)+$/;
const PHONE_RE = /^01[0-9]-?\d{3,4}-?\d{4}$/;
const ZIP_RE = /^\d{5}$/;
const REQUIRED_CONSENTS = ["terms", "privacy", "age"] as const;
const SERVICES = ["이마트", "신세계백화점", "신백멤버스", "신세계아울렛", "시코르",
  "이마트에브리데이", "신세계까사", "스타필드", "이마트24"];
const CHANNELS = ["이메일", "문자", "우편", "전화"];

const ID_RULE_MSG = "아이디는 영문 소문자를 포함해 영문, 숫자 6~20자로 입력해 주세요.";
const NICK_RULE_MSG = "닉네임은 한글, 영문, 숫자 2~10자로 입력해 주세요.";

class HttpError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

const badRequest = (message: string) => new HttpError(400, "invalid_input", message);

function passwordOk(pw: unknown): boolean {
  if (typeof pw !== "string" || pw.length < 8 || pw.length > 20 || /\s/.test(pw)) return false;
  return [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9\s]/].every((re) => re.test(pw));
}

/** '01012345678', '010-1234-5678' 을 모두 '010-1234-5678' 로 맞춘다. */
function normalizePhone(phone: string): string {
  const d = (phone || "").replace(/\D/g, "");
  if (d.length === 11) return `${d.slice(0, 3)}-${d.slice(3, 7)}-${d.slice(7)}`;
  if (d.length === 10) return `${d.slice(0, 3)}-${d.slice(3, 6)}-${d.slice(6)}`;
  return phone || "";
}

const normalizeEmail = (email: string) => email.trim().toLowerCase();

// deno-lint-ignore no-explicit-any
type Json = Record<string, any>;

function validateSignup(body: Json) {
  // 간편가입(socialTicket)은 아직 Supabase 쪽에 없다. index.ts 가 먼저 막는다.
  const userId = body.userId ?? "";
  if (typeof userId !== "string" || !ID_RE.test(userId)) throw badRequest(ID_RULE_MSG);
  if (!passwordOk(body.password)) throw badRequest("비밀번호 규칙을 확인해 주세요.");

  // 닉네임은 선택: 보낸 경우에만 규칙을 확인한다 (After 화면은 보내지 않는다)
  const nickname = body.nickname ?? "";
  if (nickname !== "" && (typeof nickname !== "string" || !NICK_RE.test(nickname.trim()))) throw badRequest(NICK_RULE_MSG);
  const name = body.name ?? "";
  if (typeof name !== "string" || name.trim().length < 1 || name.trim().length > 30) throw badRequest("이름을 확인해 주세요.");
  const phone = body.phone ?? "";
  if (typeof phone !== "string" || !PHONE_RE.test(phone.trim())) throw badRequest("휴대폰 번호를 확인해 주세요.");
  const email = body.email ?? "";
  if (typeof email !== "string" || email.length > 254 || !EMAIL_RE.test(normalizeEmail(email))) {
    throw badRequest("이메일 형식을 확인해 주세요.");
  }

  let address = null;
  if (body.address != null) {
    const a = body.address;
    if (typeof a !== "object" || Array.isArray(a)) throw badRequest("주소를 확인해 주세요.");
    const { zipcode, address1 } = a;
    const address2 = a.address2 ?? "";
    if (typeof zipcode !== "string" || !ZIP_RE.test(zipcode) || typeof address1 !== "string" ||
      !address1.trim() || typeof address2 !== "string") throw badRequest("주소를 확인해 주세요.");
    if (address1.length > 200 || address2.length > 200) throw badRequest("주소가 너무 길어요.");
    address = { zipcode, address1: address1.trim(), address2: address2.trim() };
  }

  let referrer: string | null = null;
  if (body.referrer) {
    const r = body.referrer;
    if (typeof r !== "string" || !ID_RE.test(r.trim().toLowerCase())) {
      throw new HttpError(400, "referrer_not_found", "추천인 아이디를 확인해 주세요.");
    }
    referrer = r.trim().toLowerCase();
    if (referrer === userId) throw new HttpError(400, "referrer_self", "본인 아이디는 추천인으로 입력할 수 없어요.");
  }

  return {
    userId, password: body.password as string, nickname: nickname ? nickname.trim() : null, name: name.trim(),
    phone: normalizePhone(phone.trim()), email: normalizeEmail(email), address, referrer,
  };
}

function validateConsents(c: unknown) {
  if (!c || typeof c !== "object" || Array.isArray(c)) throw badRequest("약관 동의 정보가 없어요.");
  const { required, services = {}, marketing = {} } = c as Json;
  if (!required || typeof required !== "object" || !REQUIRED_CONSENTS.every((k) => required[k] === true)) {
    throw new HttpError(400, "consent_required", "필수 약관에 모두 동의해 주세요.");
  }
  const svc = services ?? {};
  if (typeof svc !== "object" || Array.isArray(svc) || !Object.keys(svc).every((k) => SERVICES.includes(k)) ||
    !Object.values(svc).every((v) => typeof v === "boolean")) throw badRequest("서비스 동의 정보가 올바르지 않아요.");
  const mk = marketing ?? {};
  if (typeof mk !== "object" || Array.isArray(mk) ||
    !["point", "duty"].every((g) => mk[g] == null || (typeof mk[g] === "object" && !Array.isArray(mk[g])))) {
    throw badRequest("마케팅 동의 정보가 올바르지 않아요.");
  }
  const cleanMk: Json = {};
  for (const g of ["point", "duty"]) {
    cleanMk[g] = Object.fromEntries(CHANNELS.map((ch) => [ch, Boolean((mk[g] ?? {})[ch])]));
  }
  cleanMk.night = Boolean(mk.night);
  return {
    required: { terms: true, privacy: true, age: true },
    services: Object.fromEntries(SERVICES.map((s) => [s, Boolean(svc[s])])),
    marketing: cleanMk,
  };
}

// ===== 여기부터 index.ts =====
const MAX_BODY = 16 * 1024;
// 허용할 화면 주소. 비워 두면 모두 허용(시연용). 예: supabase secrets set ALLOWED_ORIGIN=https://example.com
const ALLOWED_ORIGIN = Deno.env.get("ALLOWED_ORIGIN") ?? "*";

const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
  auth: { persistSession: false, autoRefreshToken: false },
});

// DB 함수가 던지는 코드 → 화면에 보여 줄 응답
const DB_ERRORS: Record<string, [number, string]> = {
  id_taken: [409, "이미 사용 중인 아이디예요. 다른 아이디로 다시 확인해 주세요."],
  nickname_taken: [409, "이미 사용 중인 닉네임이에요. 다른 닉네임으로 다시 확인해 주세요."],
  email_unavailable: [409, "현재 이 이메일로 가입할 수 없어요. 다른 이메일을 사용해 주세요."],
  referrer_not_found: [400, "추천인 아이디를 찾을 수 없어요. 다시 확인해 주세요."],
  invalid_token: [401, "동의 내용을 수정할 수 없어요. 다시 시도해 주세요."],
  token_expired: [401, "가입 직후 수정할 수 있는 시간이 지났어요. 로그인 후 내 정보에서 바꿔 주세요."],
};

function dbError(e: { message?: string; code?: string }): HttpError {
  const hit = DB_ERRORS[e.message ?? ""];
  if (hit) return new HttpError(hit[0], e.message!, hit[1]);
  // 동시에 같은 값으로 가입해 유니크 인덱스에 걸린 경우
  if (e.code === "23505") {
    const m = e.message ?? "";
    const code = m.includes("members_nickname") ? "nickname_taken" : m.includes("members_email") ? "email_unavailable" : "id_taken";
    return new HttpError(409, code, DB_ERRORS[code][1]);
  }
  console.error("db error:", e.code, e.message);
  return new HttpError(500, "server_error", "잠시 후 다시 시도해 주세요.");
}

const cors = {
  "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
  "Access-Control-Allow-Headers": "content-type, authorization, apikey",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
};
const json = (status: number, payload: unknown) =>
  new Response(JSON.stringify(payload), {
    status,
    headers: { ...cors, "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" },
  });

async function readJson(req: Request): Promise<Record<string, unknown>> {
  if (!(req.headers.get("content-type") ?? "").includes("application/json")) {
    throw new HttpError(415, "invalid_content_type", "JSON으로 보내 주세요.");
  }
  const text = await req.text();
  if (text.length > MAX_BODY) throw new HttpError(413, "too_large", "요청이 너무 커요.");
  try {
    const data = JSON.parse(text || "{}");
    if (!data || typeof data !== "object" || Array.isArray(data)) throw 0;
    return data;
  } catch {
    throw badRequest("요청 형식이 올바르지 않아요.");
  }
}

async function sha256(value: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function newToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function exists(table: string, column: string, value: string, ci = false): Promise<boolean> {
  // ci: 대소문자 구분 없이 비교. 값은 정규식 검증을 통과한 영문·숫자·한글이라 ilike 와일드카드가 들어올 수 없다.
  const q = db.from(table).select("*", { count: "exact", head: true });
  const { count, error } = await (ci ? q.ilike(column, value) : q.eq(column, value));
  if (error) throw dbError(error);
  return (count ?? 0) > 0;
}

async function signup(body: Record<string, unknown>) {
  if (body.socialTicket) {
    throw new HttpError(501, "social_unsupported", "간편가입은 아직 이 서버에서 지원하지 않아요.");
  }
  const data = validateSignup(body);
  const consents = validateConsents(body.consents);

  // 비밀번호는 Supabase Auth 가 해시해 보관한다. 이 함수는 평문을 저장하지 않는다.
  const { data: created, error: authErr } = await db.auth.admin.createUser({
    email: data.email, password: data.password, email_confirm: true, // 이메일 소유 확인은 하지 않는 시연용
  });
  if (authErr || !created.user) {
    if (authErr && (authErr.status === 422 || /registered|exists/i.test(authErr.message))) {
      throw new HttpError(409, "email_unavailable", DB_ERRORS.email_unavailable[1]);
    }
    console.error("auth error:", authErr?.message);
    throw new HttpError(500, "server_error", "잠시 후 다시 시도해 주세요.");
  }

  const token = newToken();
  const { data: result, error } = await db.rpc("create_member", {
    p: {
      authId: created.user.id, userId: data.userId, email: data.email, name: data.name, phone: data.phone,
      nickname: data.nickname, address: data.address, referrer: data.referrer, consents,
      tokenHash: await sha256(token),
    },
  });
  if (error) {
    await db.auth.admin.deleteUser(created.user.id); // 회원 저장이 실패하면 인증 계정도 되돌린다
    throw dbError(error);
  }
  return {
    ok: true, userId: data.userId, nickname: data.nickname ?? null, consentToken: token,
    memberType: result.memberType, firstJoinedAt: result.firstJoinedAt, socialProvider: null,
  };
}

async function handle(req: Request): Promise<Response> {
  const url = new URL(req.url);
  // /functions/v1/api/users/check-id 처럼 앞에 붙는 경로와 상관없이 끝 경로로 구분한다
  const route = url.pathname.replace(/^.*?\/api(?=\/|$)/, "").replace(/^\/api(?=\/)/, "") || "/";
  const arg = (k: string) => url.searchParams.get(k) ?? "";

  if (req.method === "GET") {
    switch (route) {
      case "/health":
        return json(200, { ok: true });
      case "/users/check-id": {
        const id = arg("userId");
        if (!ID_RE.test(id)) throw badRequest(ID_RULE_MSG);
        const taken = (await exists("members", "user_id", id)) || (await exists("reserved_ids", "user_id", id));
        return json(200, { available: !taken });
      }
      case "/users/check-nickname": {
        const nick = arg("nickname").trim();
        if (!NICK_RE.test(nick)) throw badRequest(NICK_RULE_MSG);
        const taken = (await exists("members", "nickname", nick, true)) || (await exists("reserved_nicknames", "nickname", nick, true));
        return json(200, { available: !taken });
      }
      case "/users/check-referrer": {
        const id = arg("userId").trim().toLowerCase();
        if (!ID_RE.test(id)) throw badRequest("추천인 아이디를 확인해 주세요.");
        return json(200, { exists: await exists("members", "user_id", id) });
      }
      case "/auth/providers":
        return json(200, { providers: [] }); // 간편가입은 아직 옮기지 않았다
    }
  } else if (req.method === "POST") {
    const body = await readJson(req);
    switch (route) {
      case "/email/check": {
        const { email = "", phone = "" } = body;
        if (typeof email !== "string" || !EMAIL_RE.test(normalizeEmail(email))) throw badRequest("이메일 형식을 확인해 주세요.");
        if (typeof phone !== "string") throw badRequest("휴대폰 번호를 확인해 주세요.");
        const { data, error } = await db.rpc("email_status", { p_email: normalizeEmail(email), p_phone: normalizePhone(phone) });
        if (error) throw dbError(error);
        return json(200, data);
      }
      case "/signup":
        return json(201, await signup(body));
      case "/consents": {
        const token = body.consentToken;
        if (typeof token !== "string" || !token) throw new HttpError(401, "invalid_token", DB_ERRORS.invalid_token[1]);
        const consents = validateConsents(body.consents);
        const { error } = await db.rpc("update_consents", { p_token_hash: await sha256(token), c: consents });
        if (error) throw dbError(error);
        return json(200, { ok: true });
      }
      case "/auth/ticket":
        throw new HttpError(501, "social_unsupported", "간편가입은 아직 이 서버에서 지원하지 않아요.");
    }
  }
  throw new HttpError(404, "not_found", "찾을 수 없어요.");
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
  try {
    return await handle(req);
  } catch (e) {
    if (e instanceof HttpError) return json(e.status, { error: e.code, message: e.message });
    console.error("server error:", e); // 비밀번호 등이 남지 않도록 요청 본문은 기록하지 않는다
    return json(500, { error: "server_error", message: "잠시 후 다시 시도해 주세요." });
  }
});
