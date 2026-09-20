import crypto from "node:crypto";
import { normalizers as normalize } from "@trebired/utils";
import type { TwoFactorPolicy } from "#hfap0x87te96";
import { base32Decode, base32Encode } from "./base32.js";

function generateSecret(policy: TwoFactorPolicy) {
  return base32Encode(crypto.randomBytes(Math.max(10, policy.secretBytes)));
}

function hotp(secret: string, counter: number, digits: number) {
  const key = Buffer.from(base32Decode(secret));
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(Math.max(0, Math.floor(counter))));
  const digest = crypto.createHmac("sha1", key).update(message).digest();
  const offset = digest[digest.length - 1]&15;
  const binary =
  ((digest[offset]&127)<<24) |
  ((digest[offset + 1]&255)<<16) |
  ((digest[offset + 2]&255)<<8) |
  (digest[offset + 3]&255);
  return String(binary % 10 ** digits).padStart(digits, "0");
}

function totp(secret: string, policy: TwoFactorPolicy, atMs = Date.now()) {
  return hotp(secret, Math.floor(atMs / 1000 / policy.step), policy.digits);
}

function verifyTotp(secret: unknown, codeInput: unknown, policy: TwoFactorPolicy, atMs = Date.now()) {
  const key = normalize.toString(secret);
  const code = normalize.toString(codeInput).replace(/\s/gu, "");
  if (!key || code.length !== policy.digits) return false;
  const counter = Math.floor(atMs / 1000 / policy.step);
  for (let drift = -policy.window; drift <= policy.window; drift += 1) {
    const candidate = hotp(key, counter + drift, policy.digits);
    if (crypto.timingSafeEqual(Buffer.from(candidate), Buffer.from(code))) return true;
  }
  return false;
}

function otpauthUrl(secret: string, account: string, policy: TwoFactorPolicy) {
  const issuer = normalize.toString(policy.issuer);
  const label = issuer ? `${issuer}:${account}` : account;
  const params = new URLSearchParams({ algorithm: "SHA1", digits: String(policy.digits), period: String(policy.step), secret });
  if (issuer) params.set("issuer", issuer);
  return `otpauth://totp/${encodeURIComponent(label)}?${params.toString()}`;
}

export { generateSecret, hotp, otpauthUrl, totp, verifyTotp };
