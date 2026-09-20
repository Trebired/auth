import bcrypt from "bcryptjs";
import { normalizers as normalize } from "@trebired/utils";
import type { PasswordPolicy } from "#hfap0x87te96";

type PasswordRuleKey =
|"digit"
|"lowercase"
|"minLength"
|"special"
|"uppercase"
|"whitespace";

type PasswordCheck = {
  failed: PasswordRuleKey[];
  ok: boolean;
  rules: Record<PasswordRuleKey, boolean>;
  score: number;
};

const DUMMY_HASH = bcrypt.hashSync("trebired-auth-dummy-password", 10);

function hashPassword(password: string, policy: PasswordPolicy) {
  return bcrypt.hash(String(password == null ? "" : password), policy.saltRounds);
}

async function verifyPassword(password: unknown, hash: unknown) {
  const plain = normalize.toString(password);
  const stored = normalize.toString(hash);
  const target = /^\$2[aby]\$\d\d\$/iu.test(stored) ? stored : DUMMY_HASH;
  try {
    const matched = await bcrypt.compare(plain, target);
    return target === stored ? matched : false;
  } catch {
    return false;
  }
}

function passwordRules(password: string, policy: PasswordPolicy): Record<PasswordRuleKey, boolean> {
  return {
    digit: !policy.requireDigit || /[0-9]/u.test(password),
    lowercase: !policy.requireLowercase || /[a-z]/u.test(password),
    minLength: password.length >= policy.minLength,
    special: !policy.requireSpecial || /[^A-Za-z0-9]/u.test(password),
    uppercase: !policy.requireUppercase || /[A-Z]/u.test(password),
    whitespace: !policy.rejectWhitespace || !/\s/u.test(password),
  };
}

function checkPassword(passwordInput: unknown, policy: PasswordPolicy): PasswordCheck {
  const password = normalize.toString(passwordInput);
  const rules = passwordRules(password, policy);
  const failed = (Object.keys(rules) as PasswordRuleKey[]).filter((key) => !rules[key]);
  const passed = Object.values(rules).filter(Boolean).length;
  return { failed, ok: failed.length === 0, rules, score: passed };
}

export { checkPassword, hashPassword, verifyPassword };
export type { PasswordCheck, PasswordRuleKey };
