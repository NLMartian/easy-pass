export type DropboxTokenInfo = {
  accessToken?: string;
  refreshToken?: string;
  expiresAt?: string;
};

const APP_KEY_STORAGE_KEY = "easy-pass:dropbox-app-key";
const TOKEN_STORAGE_KEY = "easy-pass:dropbox-token-info";

export function loadDropboxAppKey(): string {
  return localStorage.getItem(APP_KEY_STORAGE_KEY) ?? import.meta.env.VITE_DROPBOX_APP_KEY ?? "";
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
