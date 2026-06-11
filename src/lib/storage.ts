export type DropboxTokenInfo = {
  accessToken?: string;
  refreshToken?: string;
  expiresAt?: string;
};

export type PendingVaultInfo = {
  text: string;
  savedAt: string;
  remoteRev: string | null;
};

export type BiometricUnlockInfo = {
  version: 1;
  credentialId: string;
  salt: string;
  nonce: string;
  wrappedKey: string;
  kdfSalt: string;
  createdAt: string;
  savedAt: string;
  origin: string;
};

const APP_KEY_STORAGE_KEY = "easy-pass:dropbox-app-key";
const TOKEN_STORAGE_KEY = "easy-pass:dropbox-token-info";
const PENDING_VAULT_STORAGE_KEY = "easy-pass:pending-vault";
const BIOMETRIC_UNLOCK_STORAGE_KEY = "easy-pass:biometric-unlock";
const DEFAULT_DROPBOX_APP_KEY = import.meta.env.VITE_DROPBOX_APP_KEY?.trim() || "56efgyouoypazep";

export function loadDropboxAppKey(): string {
  return localStorage.getItem(APP_KEY_STORAGE_KEY) ?? DEFAULT_DROPBOX_APP_KEY;
}

export function saveDropboxAppKey(appKey: string): void {
  if (appKey) {
    localStorage.setItem(APP_KEY_STORAGE_KEY, appKey);
  } else {
    localStorage.removeItem(APP_KEY_STORAGE_KEY);
  }
}

export function loadDropboxTokenInfo(): DropboxTokenInfo | null {
  const raw = localStorage.getItem(TOKEN_STORAGE_KEY);
  if (!raw) {
    return null;
  }

  try {
    const parsed = JSON.parse(raw) as DropboxTokenInfo;
    if (!parsed.accessToken && !parsed.refreshToken) {
      return null;
    }
    return parsed;
  } catch {
    localStorage.removeItem(TOKEN_STORAGE_KEY);
    return null;
  }
}

export function saveDropboxTokenInfo(tokens: DropboxTokenInfo | null): void {
  if (tokens && (tokens.accessToken || tokens.refreshToken)) {
    localStorage.setItem(TOKEN_STORAGE_KEY, JSON.stringify(tokens));
  } else {
    localStorage.removeItem(TOKEN_STORAGE_KEY);
  }
}

export function hasDropboxToken(tokens: DropboxTokenInfo | null): boolean {
  return Boolean(tokens?.accessToken || tokens?.refreshToken);
}

export function loadPendingVaultInfo(): PendingVaultInfo | null {
  const raw = localStorage.getItem(PENDING_VAULT_STORAGE_KEY);
  if (!raw) {
    return null;
  }

  try {
    const parsed = JSON.parse(raw) as PendingVaultInfo;
    if (
      typeof parsed.text !== "string" ||
      typeof parsed.savedAt !== "string" ||
      (typeof parsed.remoteRev !== "string" && parsed.remoteRev !== null)
    ) {
      localStorage.removeItem(PENDING_VAULT_STORAGE_KEY);
      return null;
    }
    return parsed;
  } catch {
    localStorage.removeItem(PENDING_VAULT_STORAGE_KEY);
    return null;
  }
}

export function savePendingVaultInfo(pendingVault: PendingVaultInfo): void {
  localStorage.setItem(PENDING_VAULT_STORAGE_KEY, JSON.stringify(pendingVault));
}

export function clearPendingVaultInfo(): void {
  localStorage.removeItem(PENDING_VAULT_STORAGE_KEY);
}

export function loadBiometricUnlockInfo(): BiometricUnlockInfo | null {
  const raw = localStorage.getItem(BIOMETRIC_UNLOCK_STORAGE_KEY);
  if (!raw) {
    return null;
  }

  try {
    const parsed = JSON.parse(raw) as BiometricUnlockInfo;
    if (
      parsed.version !== 1 ||
      typeof parsed.credentialId !== "string" ||
      typeof parsed.salt !== "string" ||
      typeof parsed.nonce !== "string" ||
      typeof parsed.wrappedKey !== "string" ||
      typeof parsed.kdfSalt !== "string" ||
      typeof parsed.createdAt !== "string" ||
      typeof parsed.savedAt !== "string" ||
      typeof parsed.origin !== "string"
    ) {
      localStorage.removeItem(BIOMETRIC_UNLOCK_STORAGE_KEY);
      return null;
    }
    return parsed;
  } catch {
    localStorage.removeItem(BIOMETRIC_UNLOCK_STORAGE_KEY);
    return null;
  }
}

export function saveBiometricUnlockInfo(info: BiometricUnlockInfo): void {
  localStorage.setItem(BIOMETRIC_UNLOCK_STORAGE_KEY, JSON.stringify(info));
}

export function clearBiometricUnlockInfo(): void {
  localStorage.removeItem(BIOMETRIC_UNLOCK_STORAGE_KEY);
}
