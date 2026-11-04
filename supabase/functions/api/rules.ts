// 입력 규칙과 검증. Deno/Node 어디서든 도는 순수 코드 (index.ts 의 DB 호출과 분리)
// index.html 의 프런트 규칙, 이전 server.py 와 같게 유지한다.

export const ID_RE = /^(?=.*[a-z])[a-z0-9]{6,20}$/;
export const NICK_RE = /^[가-힣A-Za-z0-9]{2,10}$/;
export const EMAIL_RE = /^[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)+$/;
export const PHONE_RE = /^01[0-9]-?\d{3,4}-?\d{4}$/;
export const ZIP_RE = /^\d{5}$/;
export const REQUIRED_CONSENTS = ["terms", "privacy", "age"] as const;
export const SERVICES = ["이마트", "신세계백화점", "신백멤버스", "신세계아울렛", "시코르",
  "이마트에브리데이", "신세계까사", "스타필드", "이마트24"];
export const CHANNELS = ["이메일", "문자", "우편", "전화"];

export const ID_RULE_MSG = "아이디는 영문 소문자를 포함해 영문, 숫자 6~20자로 입력해 주세요.";
export const NICK_RULE_MSG = "닉네임은 한글, 영문, 숫자 2~10자로 입력해 주세요.";

export class HttpError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export const badRequest = (message: string) => new HttpError(400, "invalid_input", message);

export function passwordOk(pw: unknown): boolean {
  if (typeof pw !== "string" || pw.length < 8 || pw.length > 20 || /\s/.test(pw)) return false;
  return [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9\s]/].every((re) => re.test(pw));
}

/** '01012345678', '010-1234-5678' 을 모두 '010-1234-5678' 로 맞춘다. */
export function normalizePhone(phone: string): string {
  const d = (phone || "").replace(/\D/g, "");
  if (d.length === 11) return `${d.slice(0, 3)}-${d.slice(3, 7)}-${d.slice(7)}`;
  if (d.length === 10) return `${d.slice(0, 3)}-${d.slice(3, 6)}-${d.slice(6)}`;
  return phone || "";
}

export const normalizeEmail = (email: string) => email.trim().toLowerCase();

// deno-lint-ignore no-explicit-any
type Json = Record<string, any>;

export function validateSignup(body: Json) {
  // 간편가입(socialTicket)은 아직 Supabase 쪽에 없다. index.ts 가 먼저 막는다.
  const userId = body.userId ?? "";
  if (typeof userId !== "string" || !ID_RE.test(userId)) throw badRequest(ID_RULE_MSG);
  if (!passwordOk(body.password)) throw badRequest("비밀번호 규칙을 확인해 주세요.");

  const nickname = body.nickname ?? "";
  if (typeof nickname !== "string" || !NICK_RE.test(nickname.trim())) throw badRequest(NICK_RULE_MSG);
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
    userId, password: body.password as string, nickname: nickname.trim(), name: name.trim(),
    phone: normalizePhone(phone.trim()), email: normalizeEmail(email), address, referrer,
  };
}

export function validateConsents(c: unknown) {
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
