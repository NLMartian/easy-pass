import type { VaultKeyContext } from "../types";
import type { BiometricUnlockInfo } from "./storage";
import { base64ToBytes, bytesToBase64, randomBytes } from "./encoding";

const encoder = new TextEncoder();
const WEBAUTHN_TIMEOUT_MS = 60_000;
const PRF_SALT_LENGTH = 32;
const WRAP_AAD = encoder.encode("easy-pass:biometric-unlock:v1");
const HKDF_SALT = encoder.encode("easy-pass:webauthn-prf:hkdf-salt:v1");
const HKDF_INFO = encoder.encode("easy-pass:vault-key-wrap:v1");

type PublicKeyCredentialWithRawId = PublicKeyCredential & {
  rawId: ArrayBuffer;
};

type PrfExtensionResults = {
  prf?: {
    enabled?: boolean;
    results?: {
      first?: ArrayBuffer;
    };
  };
};

export function canUseBiometricUnlock(): boolean {
  return Boolean(
    window.isSecureContext &&
      "PublicKeyCredential" in window &&
      typeof navigator.credentials?.create === "function" &&
      typeof navigator.credentials?.get === "function",
  );
}

export async function createBiometricUnlockInfo(
  rawVaultKey: Uint8Array,
  keyContext: VaultKeyContext,
): Promise<BiometricUnlockInfo> {
  assertWebAuthnAvailable();

  const salt = randomBytes(PRF_SALT_LENGTH);
  const credential = await createCredential();
  const credentialId = bytesToBase64(new Uint8Array(credential.rawId));
  const prfSecret = await evaluatePrf(credential.rawId, salt);
  const wrappingKey = await deriveWrappingKey(prfSecret);
  const nonce = randomBytes(12);
  const wrappedKey = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: toArrayBuffer(nonce),
      additionalData: toArrayBuffer(WRAP_AAD),
    },
    wrappingKey,
    toArrayBuffer(rawVaultKey),
  );

  prfSecret.fill(0);

  return {
    version: 1,
    credentialId,
    salt: bytesToBase64(salt),
    nonce: bytesToBase64(nonce),
    wrappedKey: bytesToBase64(new Uint8Array(wrappedKey)),
    kdfSalt: keyContext.kdf.salt,
    createdAt: keyContext.createdAt,
    savedAt: new Date().toISOString(),
    origin: window.location.origin,
  };
}

export async function unwrapBiometricVaultKey(info: BiometricUnlockInfo): Promise<Uint8Array> {
  assertWebAuthnAvailable();
  if (info.origin !== window.location.origin) {
    throw new Error("本机生物识别解锁信息来自不同站点，不能在当前地址使用。");
  }

  const credentialId = base64ToBytes(info.credentialId);
  const prfSecret = await evaluatePrf(credentialId, base64ToBytes(info.salt));
  const wrappingKey = await deriveWrappingKey(prfSecret);
  try {
    const rawKey = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: toArrayBuffer(base64ToBytes(info.nonce)),
        additionalData: toArrayBuffer(WRAP_AAD),
      },
      wrappingKey,
      toArrayBuffer(base64ToBytes(info.wrappedKey)),
    );
    return new Uint8Array(rawKey);
  } catch {
    throw new Error("本机生物识别解锁信息已失效，请用主密码解锁后重新启用。");
  } finally {
    prfSecret.fill(0);
  }
}

async function createCredential(): Promise<PublicKeyCredentialWithRawId> {
  const credential = (await navigator.credentials.create({
    publicKey: {
      challenge: toArrayBuffer(randomBytes(32)),
      rp: {
        name: "Easy Pass",
      },
      user: {
        id: toArrayBuffer(randomBytes(16)),
        name: "easy-pass-local-unlock",
        displayName: "Easy Pass",
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        residentKey: "preferred",
        userVerification: "required",
      },
      timeout: WEBAUTHN_TIMEOUT_MS,
      attestation: "none",
      extensions: {
        prf: {},
      },
    } as PublicKeyCredentialCreationOptions & { extensions: { prf: object } },
  })) as PublicKeyCredentialWithRawId | null;

  if (!credential?.rawId) {
    throw new Error("没有创建可用于本机解锁的 WebAuthn 凭据。");
  }

  const extensionResults = credential.getClientExtensionResults() as PrfExtensionResults;
  if (extensionResults.prf && extensionResults.prf.enabled === false) {
    throw new Error("此设备的验证器不支持 WebAuthn PRF，无法安全启用生物识别解锁。");
  }

  return credential;
}

async function evaluatePrf(credentialId: ArrayBuffer | Uint8Array, salt: Uint8Array): Promise<Uint8Array> {
  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge: toArrayBuffer(randomBytes(32)),
      allowCredentials: [
        {
          id: toArrayBuffer(credentialId),
          type: "public-key",
        },
      ],
      userVerification: "required",
      timeout: WEBAUTHN_TIMEOUT_MS,
      extensions: {
        prf: {
          eval: {
            first: toArrayBuffer(salt),
          },
        },
      },
    } as PublicKeyCredentialRequestOptions & {
      extensions: {
        prf: {
          eval: {
            first: ArrayBuffer;
          };
        };
      };
    },
  })) as PublicKeyCredential | null;

  const results = assertion?.getClientExtensionResults() as PrfExtensionResults | undefined;
  const first = results?.prf?.results?.first;
  if (!first) {
    throw new Error("当前设备或浏览器不支持 WebAuthn PRF，无法安全使用指纹/面容解锁。");
  }

  return new Uint8Array(first);
}

async function deriveWrappingKey(prfSecret: Uint8Array): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey("raw", toArrayBuffer(prfSecret), "HKDF", false, [
    "deriveKey",
  ]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: toArrayBuffer(HKDF_SALT),
      info: toArrayBuffer(HKDF_INFO),
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function assertWebAuthnAvailable(): void {
  if (!canUseBiometricUnlock()) {
    throw new Error("当前浏览器或访问地址不支持 WebAuthn。请使用 HTTPS 或 localhost。");
  }
}

function toArrayBuffer(bytes: Uint8Array | ArrayBuffer): ArrayBuffer {
  if (bytes instanceof ArrayBuffer) {
    const copy = new Uint8Array(bytes.byteLength);
    copy.set(new Uint8Array(bytes));
    return copy.buffer;
  }
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}
