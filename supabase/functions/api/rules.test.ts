// 실행: node --test supabase/functions/api/rules.test.ts   (Node 22.6+)
import { test } from "node:test";
import assert from "node:assert/strict";
import { HttpError, normalizePhone, passwordOk, validateConsents, validateSignup } from "./rules.ts";

const base = {
  userId: "tester01", password: "Abcd123!", nickname: "테스터", name: "김신세",
  phone: "01012345678", email: " Test@Example.com ",
};
const req = { terms: true, privacy: true, age: true };

test("비밀번호 규칙", () => {
  assert.equal(passwordOk("Abcd123!"), true);
  for (const bad of ["abcd123!", "ABCD123!", "Abcdefg!", "Abcd1234", "Ab1!", "Abcd 123!", "A".repeat(21) + "a1!"]) {
    assert.equal(passwordOk(bad), false, bad);
  }
});

test("휴대폰 정규화", () => {
  assert.equal(normalizePhone("01012345678"), "010-1234-5678");
  assert.equal(normalizePhone("0111234567"), "011-123-4567");
});

test("가입 입력 정리", () => {
  const d = validateSignup(base);
  assert.equal(d.email, "test@example.com");
  assert.equal(d.phone, "010-1234-5678");
  assert.equal(validateSignup({ ...base, nickname: undefined }).nickname, null); // 닉네임 없이도 가입 입력이 통과한다
});

test("가입 입력 거절", () => {
  const code = (body: object) => { try { validateSignup(body as never); } catch (e) { return (e as HttpError).code; } };
  assert.equal(code({ ...base, userId: "ABC" }), "invalid_input");
  assert.equal(code({ ...base, nickname: "a" }), "invalid_input");
  assert.equal(code({ ...base, referrer: "tester01" }), "referrer_self");
  assert.equal(code({ ...base, address: { zipcode: "123", address1: "x" } }), "invalid_input");
});

test("약관 동의", () => {
  const c = validateConsents({ required: req, services: { 이마트: true } });
  assert.equal(c.services["이마트"], true);
  assert.equal(c.services["스타필드"], false);
  assert.equal(c.marketing.point["이메일"], false);
  assert.throws(() => validateConsents({ required: { terms: true } }), { code: "consent_required" });
  assert.throws(() => validateConsents({ required: req, services: { 없는서비스: true } }));
});
