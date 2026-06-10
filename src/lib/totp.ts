import type { TotpConfig } from "../types";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export type TotpCode = {
  code: string;
  secondsRemaining: number;
  period: number;
};

export function parseTotpInput(input: string): TotpConfig {
  const trimmed = input.trim();
  if (!trimmed) {
    throw new Error("请输入一次性密码密钥。");
  }

  if (trimmed.toLowerCase().startsWith("otpauth://")) {
    return parseOtpAuthUri(trimmed);
  }

  const secret = normalizeBase32Secret(trimmed);
  decodeBase32(secret);
  return {
    secret,
    issuer: "",
    account: "",
    algorithm: "SHA-1",
    digits: 6,
    period: 30,
  };
}

export async function generateTotp(config: TotpConfig, now = Date.now()): Promise<TotpCode> {
  const period = config.period || 30;
  const counter = Math.floor(now / 1000 / period);
  const secondsRemaining = period - (Math.floor(now / 1000) % period);
  const keyData = decodeBase32(config.secret);
  const key = await crypto.subtle.importKey(
    "raw",
    keyData,
    {
      name: "HMAC",
      hash: config.algorithm || "SHA-1",
    },
    false,
    ["sign"],
  );

  const counterData = new ArrayBuffer(8);
  const view = new DataView(counterData);
  view.setUint32(4, counter, false);
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterData));
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  const modulo = 10 ** (config.digits || 6);

  return {
    code: String(binary % modulo).padStart(config.digits || 6, "0"),
    secondsRemaining,
    period,
  };
}

export function normalizeBase32Secret(secret: string): string {
  return secret.replace(/[\s=-]/g, "").toUpperCase();
}

function parseOtpAuthUri(value: string): TotpConfig {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("otpauth URI 格式不正确。");
  }

  if (url.protocol !== "otpauth:" || url.hostname !== "totp") {
    throw new Error("仅支持 otpauth://totp URI。");
  }

  const secret = normalizeBase32Secret(url.searchParams.get("secret") ?? "");
  if (!secret) {
    throw new Error("otpauth URI 缺少 secret。");
  }
  decodeBase32(secret);

  const label = decodeURIComponent(url.pathname.replace(/^\//, ""));
  const [labelIssuer, ...accountParts] = label.split(":");
  const issuer = url.searchParams.get("issuer") || (accountParts.length ? labelIssuer : "");
  const account = accountParts.length ? accountParts.join(":") : labelIssuer;
  const algorithm = normalizeAlgorithm(url.searchParams.get("algorithm"));
  const digits = normalizeNumber(url.searchParams.get("digits"), 6, 6, 8, "digits");
  const period = normalizeNumber(url.searchParams.get("period"), 30, 15, 120, "period");

  return {
    secret,
    issuer,
    account,
    algorithm,
    digits,
    period,
  };
}

function decodeBase32(secret: string): ArrayBuffer {
  const normalized = normalizeBase32Secret(secret);
  let bits = "";
  for (const character of normalized) {
    const value = BASE32_ALPHABET.indexOf(character);
    if (value === -1) {
      throw new Error("TOTP secret 不是有效的 Base32。");
    }
    bits += value.toString(2).padStart(5, "0");
  }

  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(bits.slice(index * 8, index * 8 + 8), 2);
  }
  return bytes.buffer;
}

function normalizeAlgorithm(value: string | null): TotpConfig["algorithm"] {
  const normalized = (value || "SHA1").replace("-", "").toUpperCase();
  if (normalized === "SHA256") return "SHA-256";
  if (normalized === "SHA512") return "SHA-512";
  return "SHA-1";
}

function normalizeNumber(
  value: string | null,
  fallback: number,
  min: number,
  max: number,
  label: string,
): number {
  if (!value) return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`TOTP ${label} 参数不合法。`);
  }
  return parsed;
}
