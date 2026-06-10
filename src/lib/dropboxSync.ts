import { Dropbox, DropboxAuth, DropboxResponseError } from "dropbox";
import type { DropboxResponse, files } from "dropbox";
import type { DropboxTokenInfo } from "./storage";
import { randomBytes } from "./encoding";
import { VAULT_FILE_NAME } from "./vault";

const OAUTH_STATE_KEY = "easy-pass:dropbox-oauth-state";
const OAUTH_VERIFIER_KEY = "easy-pass:dropbox-code-verifier";
const DROPBOX_SCOPES = ["files.content.read", "files.content.write", "files.metadata.read"];
const VAULT_PATH = `/${VAULT_FILE_NAME}`;
const dropboxFetch: typeof fetch = (input, init) => window.fetch(input, init);
let pendingOAuthCompletion: { key: string; promise: Promise<DropboxTokenInfo | null> } | null = null;

export type RemoteVault = {
  text: string;
  rev: string;
  serverModified: string;
  size: number;
};

export type DropboxClientContext = {
  dbx: Dropbox;
  tokens: DropboxTokenInfo;
};

type OAuthTokenResult = {
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
};

type DownloadResult = files.FileMetadata & {
  fileBlob?: Blob;
  fileBinary?: unknown;
};

export function hasOAuthRedirect(): boolean {
  const params = new URLSearchParams(window.location.search);
  return params.has("code") || params.has("error");
}

export function getDropboxRedirectUri(): string {
  return `${window.location.origin}${window.location.pathname}`;
}

export async function startDropboxAuth(appKey: string): Promise<void> {
  const auth = new DropboxAuth({ clientId: appKey, fetch: dropboxFetch });
  const state = oauthRandomString();
  const authUrl = await auth.getAuthenticationUrl(
    getDropboxRedirectUri(),
    state,
    "code",
    "offline",
    DROPBOX_SCOPES,
    "none",
    true,
  );

  sessionStorage.setItem(OAUTH_STATE_KEY, state);
  sessionStorage.setItem(OAUTH_VERIFIER_KEY, auth.getCodeVerifier());
  window.location.assign(String(authUrl));
}

export function completeDropboxAuth(appKey: string): Promise<DropboxTokenInfo | null> {
  const url = new URL(window.location.href);
  const code = url.searchParams.get("code");
  const returnedState = url.searchParams.get("state");
  const oauthError = url.searchParams.get("error_description") ?? url.searchParams.get("error");

  if (code) {
    const completionKey = `${appKey}:${returnedState ?? ""}:${code}`;
    if (pendingOAuthCompletion?.key === completionKey) {
      return pendingOAuthCompletion.promise;
    }

    const promise = completeDropboxAuthOnce(appKey, code, returnedState, oauthError).finally(() => {
      if (pendingOAuthCompletion?.key === completionKey) {
        pendingOAuthCompletion = null;
      }
    });
    pendingOAuthCompletion = { key: completionKey, promise };
    return promise;
  }

  return completeDropboxAuthOnce(appKey, code, returnedState, oauthError);
}

async function completeDropboxAuthOnce(
  appKey: string,
  code: string | null,
  returnedState: string | null,
  oauthError: string | null,
): Promise<DropboxTokenInfo | null> {
  try {
    if (oauthError) {
      throw new Error(`Dropbox 授权失败：${oauthError}`);
    }
    if (!code) {
      return null;
    }

    const expectedState = sessionStorage.getItem(OAUTH_STATE_KEY);
    const codeVerifier = sessionStorage.getItem(OAUTH_VERIFIER_KEY);
    if (!expectedState || returnedState !== expectedState || !codeVerifier) {
      throw new Error("Dropbox 授权状态不匹配，请重新连接。");
    }

    const auth = new DropboxAuth({ clientId: appKey, fetch: dropboxFetch });
    auth.setCodeVerifier(codeVerifier);
    const response = await auth.getAccessTokenFromCode(getDropboxRedirectUri(), code);
    const result = response.result as OAuthTokenResult;
    if (!result.access_token) {
      throw new Error("Dropbox 没有返回 access token。");
    }

    return {
      accessToken: result.access_token,
      refreshToken: result.refresh_token,
      expiresAt: result.expires_in ? new Date(Date.now() + result.expires_in * 1000).toISOString() : undefined,
    };
  } finally {
    sessionStorage.removeItem(OAUTH_STATE_KEY);
    sessionStorage.removeItem(OAUTH_VERIFIER_KEY);
    clearOAuthQueryParams();
  }
}

export async function createDropboxClient(appKey: string, tokens: DropboxTokenInfo): Promise<DropboxClientContext> {
  const auth = new DropboxAuth({
    clientId: appKey,
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken,
    accessTokenExpiresAt: tokens.expiresAt ? new Date(tokens.expiresAt) : undefined,
    fetch: dropboxFetch,
  });

  await (auth.checkAndRefreshAccessToken() as unknown as Promise<void>);
  const nextTokens = readTokensFromAuth(auth, tokens);
  return {
    dbx: new Dropbox({ auth }),
    tokens: nextTokens,
  };
}

export async function downloadRemoteVault(dbx: Dropbox): Promise<RemoteVault | null> {
  try {
    const response = (await dbx.filesDownload({ path: VAULT_PATH })) as DropboxResponse<DownloadResult>;
    const blob = response.result.fileBlob;
    if (!blob) {
      throw new Error("当前运行环境没有返回可读取的 Dropbox 文件内容。");
    }

    return {
      text: await blob.text(),
      rev: response.result.rev,
      serverModified: response.result.server_modified,
      size: response.result.size,
    };
  } catch (error) {
    if (isDropboxNotFound(error)) {
      return null;
    }
    throw error;
  }
}

export async function uploadRemoteVault(dbx: Dropbox, text: string, knownRev: string | null): Promise<RemoteVault> {
  const response = await dbx.filesUpload({
    path: VAULT_PATH,
    mode: knownRev ? { ".tag": "update", update: knownRev } : { ".tag": "add" },
    autorename: false,
    mute: true,
    client_modified: toDropboxTimestamp(new Date()),
    contents: new Blob([text], { type: "application/octet-stream" }),
  });

  return {
    text,
    rev: response.result.rev,
    serverModified: response.result.server_modified,
    size: response.result.size,
  };
}

export function isDropboxConflict(error: unknown): boolean {
  const summary = getDropboxErrorSummary(error);
  return getDropboxStatus(error) === 409 && summary.includes("conflict");
}

export function formatDropboxError(error: unknown): string {
  const status = getDropboxStatus(error);
  if (status) {
    const summary = getDropboxErrorSummary(error);
    if (status === 401) {
      return "Dropbox token 已失效，请重新连接。";
    }
    if (summary.includes("missing_scope")) {
      return "Dropbox token 缺少权限。请在 Dropbox App 的 Permissions 勾选 files.content.read、files.content.write、files.metadata.read，保存后移除本机 token 并重新连接。";
    }
    if (summary.includes("conflict")) {
      return `Dropbox 写入冲突：/${VAULT_FILE_NAME} 可能已经存在或远端版本已变化。请先读取 Dropbox 后再操作。`;
    }
    if (summary.includes("not_found")) {
      return `Dropbox 中还没有 /${VAULT_FILE_NAME}。`;
    }
    if (summary) {
      return `Dropbox API ${status}: ${summary}`;
    }
    return `Dropbox API ${status}`;
  }
  return error instanceof Error ? error.message : "Dropbox 操作失败。";
}

function readTokensFromAuth(auth: DropboxAuth, previous: DropboxTokenInfo): DropboxTokenInfo {
  const expiresAt = auth.getAccessTokenExpiresAt();
  return {
    accessToken: auth.getAccessToken() || previous.accessToken,
    refreshToken: auth.getRefreshToken() || previous.refreshToken,
    expiresAt: expiresAt ? expiresAt.toISOString() : previous.expiresAt,
  };
}

function isDropboxNotFound(error: unknown): boolean {
  return getDropboxStatus(error) === 409 && getDropboxErrorSummary(error).includes("not_found");
}

function getDropboxStatus(error: unknown): number | null {
  if (error instanceof DropboxResponseError) {
    return error.status;
  }
  if (error && typeof error === "object" && "status" in error && typeof error.status === "number") {
    return error.status;
  }
  return null;
}

function getDropboxErrorSummary(error: unknown): string {
  const payload =
    error && typeof error === "object" && "error" in error
      ? (error.error as { error_summary?: string; error?: unknown; error_description?: string } | string | undefined)
      : undefined;

  if (typeof payload === "string") {
    return payload;
  }

  const parts = [
    payload?.error_summary,
    payload?.error_description,
    typeof payload?.error === "string" ? payload.error : undefined,
    payload?.error ? JSON.stringify(payload.error) : undefined,
  ];
  return parts.filter(Boolean).join(" ");
}

function clearOAuthQueryParams(): void {
  const url = new URL(window.location.href);
  url.searchParams.delete("code");
  url.searchParams.delete("state");
  url.searchParams.delete("error");
  url.searchParams.delete("error_description");
  window.history.replaceState({}, document.title, `${url.pathname}${url.search}${url.hash}`);
}

function oauthRandomString(): string {
  return Array.from(randomBytes(32), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function toDropboxTimestamp(date: Date): string {
  return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}
