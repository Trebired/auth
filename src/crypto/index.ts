import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";
import { normalizers as normalize } from "@trebired/utils";
import type { SecretCipher } from "#hfap0x87te96";

const ALGORITHM = "aes-256-gcm";
const DERIVATION_SALT = "trebired.auth.secret";
const IV_BYTES = 12;
const KEY_BYTES = 32;
const VERSION = "v1";

function deriveKey(key: string) {
  return scryptSync(key, DERIVATION_SALT, KEY_BYTES);
}

function createSecretCipher(keyInput: unknown): SecretCipher {
  const key = normalize.toString(keyInput);
  if (!key) throw new Error("auth: a secret cipher needs a key");
  const derived = deriveKey(key);

  function encrypt(value: unknown) {
    const text = normalize.toString(value);
    if (!text) return "";
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv(ALGORITHM, derived, iv);
    const body = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
    return [VERSION, iv.toString("hex"), cipher.getAuthTag().toString("hex"), body.toString("hex")].join(":");
  }

  function decrypt(value: unknown) {
    const parts = normalize.toString(value).split(":");
    if (parts.length !== 4 || parts[0] !== VERSION) return "";
    try {
      const decipher = createDecipheriv(ALGORITHM, derived, Buffer.from(parts[1], "hex"));
      decipher.setAuthTag(Buffer.from(parts[2], "hex"));
      return Buffer.concat([decipher.update(Buffer.from(parts[3], "hex")), decipher.final()]).toString("utf8");
    } catch {
      return "";
    }
  }

  return { decrypt, encrypt };
}

function isEncryptedSecret(value: unknown) {
  const parts = normalize.toString(value).split(":");
  return parts.length === 4 && parts[0] === VERSION;
}

export { createSecretCipher, isEncryptedSecret };
