// Supabase Edge Function: 회원가입 API (이전 server.py 와 같은 요청/응답)
// 배포: supabase functions deploy api   (config.toml 에서 verify_jwt = false)
// 주소: https://<프로젝트>.supabase.co/functions/v1/api/<경로>
import { createClient } from "npm:@supabase/supabase-js@2.45.4";
import {
  badRequest, EMAIL_RE, HttpError, ID_RE, ID_RULE_MSG, NICK_RE, NICK_RULE_MSG, normalizeEmail, normalizePhone,
  validateConsents, validateSignup,
} from "./rules.ts";

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
    ok: true, userId: data.userId, nickname: data.nickname, consentToken: token,
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
