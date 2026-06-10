import { argon2id } from "hash-wasm";
import type { KdfParams, VaultData, VaultEnvelope, VaultKeyContext, VaultSession } from "../types";
import { base64ToBytes, bytesToBase64, randomBytes } from "./encoding";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const VAULT_AAD = encoder.encode("easy-pass:vault:v1");

export const VAULT_FILE_NAME = "vault.enc";

export const DEFAULT_KDF: Omit<KdfParams, "salt"> = {
  name: "Argon2id",
  memoryKiB: 64 * 1024,
  iterations: 3,
  parallelism: 1,
  hashLength: 32,
};

export type SealedVault = {
  text: string;
  data: VaultData;
};

export function createEmptyVault(): VaultData {
  const now = new Date().toISOString();
  return {
    version: 1,
    meta: {
      createdAt: now,
      updatedAt: now,
    },
    items: [],
  };
}

export async function createVaultSession(masterPassword: string): Promise<VaultSession> {
  const createdAt = new Date().toISOString();
  const kdf: KdfParams = {
    ...DEFAULT_KDF,
    salt: bytesToBase64(randomBytes(16)),
  };

  return {
    data: createEmptyVault(),
    keyContext: {
      key: await deriveAesKey(masterPassword, kdf),
      kdf,
      createdAt,
    },
  };
}

export async function unlockVault(encryptedVault: string, masterPassword: string): Promise<VaultSession> {
  const envelope = parseEnvelope(encryptedVault);
  const key = await deriveAesKey(masterPassword, envelope.kdf);
  return decryptEnvelope(envelope, key);
}

export async function unlockVaultWithKeyContext(
  encryptedVault: string,
  keyContext: VaultKeyContext,
): Promise<VaultSession> {
  const envelope = parseEnvelope(encryptedVault);
  if (
    envelope.kdf.salt !== keyContext.kdf.salt ||
    envelope.kdf.memoryKiB !== keyContext.kdf.memoryKiB ||
    envelope.kdf.iterations !== keyContext.kdf.iterations ||
    envelope.kdf.parallelism !== keyContext.kdf.parallelism ||
    envelope.kdf.hashLength !== keyContext.kdf.hashLength
  ) {
    throw new Error("远端 vault.enc 使用了不同的密钥参数，请锁定后用主密码重新解锁。");
  }
  return decryptEnvelope(envelope, keyContext.key);
}

export async function sealVault(session: VaultSession): Promise<SealedVault> {
  const updatedAt = new Date().toISOString();
  const data: VaultData = {
    ...session.data,
    meta: {
      ...session.data.meta,
      updatedAt,
    },
  };
  const nonce = randomBytes(12);
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: toArrayBuffer(nonce),
      additionalData: toArrayBuffer(VAULT_AAD),
    },
    session.keyContext.key,
    toArrayBuffer(encoder.encode(JSON.stringify(data))),
  );

  const envelope: VaultEnvelope = {
    app: "easy-pass",
    version: 1,
    cipher: "AES-256-GCM",
    kdf: session.keyContext.kdf,
    nonce: bytesToBase64(nonce),
    createdAt: session.keyContext.createdAt,
    updatedAt,
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
  };

  return {
    text: `${JSON.stringify(envelope, null, 2)}\n`,
    data,
  };
}

async function decryptEnvelope(envelope: VaultEnvelope, key: CryptoKey): Promise<VaultSession> {
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: toArrayBuffer(base64ToBytes(envelope.nonce)),
        additionalData: toArrayBuffer(VAULT_AAD),
      },
      key,
      toArrayBuffer(base64ToBytes(envelope.ciphertext)),
    );
  } catch {
    throw new Error("主密码错误，或 vault.enc 已损坏。");
  }

  return {
    data: parseVaultData(decoder.decode(plaintext)),
    keyContext: {
      key,
      kdf: envelope.kdf,
      createdAt: envelope.createdAt,
    },
  };
}

async function deriveAesKey(masterPassword: string, kdf: KdfParams): Promise<CryptoKey> {
  if (!masterPassword) {
    throw new Error("请输入主密码。");
  }
  const rawKey = await argon2id({
    password: masterPassword,
    salt: base64ToBytes(kdf.salt),
    iterations: kdf.iterations,
    parallelism: kdf.parallelism,
    memorySize: kdf.memoryKiB,
    hashLength: kdf.hashLength,
    outputType: "binary",
  });

  try {
    return await crypto.subtle.importKey("raw", toArrayBuffer(rawKey), { name: "AES-GCM" }, false, [
      "encrypt",
      "decrypt",
    ]);
  } finally {
    rawKey.fill(0);
  }
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function parseEnvelope(raw: string): VaultEnvelope {
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new Error("vault.enc 格式不是有效 JSON。");
  }

  if (!isEnvelope(value)) {
    throw new Error("vault.enc 不是 Easy Pass v1 加密文件。");
  }
  return value;
}

function parseVaultData(raw: string): VaultData {
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new Error("主密码错误，或 vault.enc 已损坏。");
  }

  if (!isVaultData(value)) {
    throw new Error("解密成功，但密码库数据结构不受支持。");
  }
  return value;
}

function isEnvelope(value: unknown): value is VaultEnvelope {
  if (!value || typeof value !== "object") {
    return false;
  }
  const candidate = value as VaultEnvelope;
  return (
    candidate.app === "easy-pass" &&
    candidate.version === 1 &&
    candidate.cipher === "AES-256-GCM" &&
    typeof candidate.nonce === "string" &&
    typeof candidate.createdAt === "string" &&
    typeof candidate.updatedAt === "string" &&
    typeof candidate.ciphertext === "string" &&
    isKdf(candidate.kdf)
  );
}

function isKdf(value: unknown): value is KdfParams {
  if (!value || typeof value !== "object") {
    return false;
  }
  const candidate = value as KdfParams;
  return (
    candidate.name === "Argon2id" &&
    Number.isInteger(candidate.memoryKiB) &&
    Number.isInteger(candidate.iterations) &&
    Number.isInteger(candidate.parallelism) &&
    Number.isInteger(candidate.hashLength) &&
    typeof candidate.salt === "string"
  );
}

function isVaultData(value: unknown): value is VaultData {
  if (!value || typeof value !== "object") {
    return false;
  }
  const candidate = value as VaultData;
  return (
    candidate.version === 1 &&
    Boolean(candidate.meta) &&
    typeof candidate.meta.createdAt === "string" &&
    typeof candidate.meta.updatedAt === "string" &&
    Array.isArray(candidate.items) &&
    candidate.items.every((item) => {
      const maybeItem = item as Record<string, unknown>;
      return (
        typeof maybeItem.id === "string" &&
        typeof maybeItem.title === "string" &&
        typeof maybeItem.username === "string" &&
        typeof maybeItem.password === "string" &&
        typeof maybeItem.url === "string" &&
        typeof maybeItem.notes === "string" &&
        Array.isArray(maybeItem.tags) &&
        maybeItem.tags.every((tag) => typeof tag === "string") &&
        typeof maybeItem.createdAt === "string" &&
        typeof maybeItem.updatedAt === "string"
      );
    })
  );
}
