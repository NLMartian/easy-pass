import {
  Check,
  Cloud,
  CloudOff,
  Copy,
  Download,
  Eye,
  EyeOff,
  Fingerprint,
  History,
  KeyRound,
  Lock,
  LogOut,
  Pencil,
  Plus,
  RefreshCw,
  Save,
  Search,
  Settings,
  ShieldCheck,
  Trash2,
  WandSparkles,
  X,
} from "lucide-react";
import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  completeDropboxAuth,
  createDropboxClient,
  downloadRemoteVault,
  formatDropboxError,
  getDropboxRedirectUri,
  getRemoteVaultMetadata,
  hasOAuthRedirect,
  isDropboxConflict,
  RemoteVault,
  startDropboxAuth,
  uploadRemoteVault,
} from "./lib/dropboxSync";
import { randomId } from "./lib/encoding";
import {
  canUseBiometricUnlock,
  createBiometricUnlockInfo,
  unwrapBiometricVaultKey,
} from "./lib/biometricUnlock";
import {
  DEFAULT_PASSWORD_OPTIONS,
  generatePassword,
  MAX_GENERATED_PASSWORD_LENGTH,
  MIN_GENERATED_PASSWORD_LENGTH,
  PasswordGeneratorOptions,
} from "./lib/passwords";
import {
  BiometricUnlockInfo,
  DropboxTokenInfo,
  clearBiometricUnlockInfo,
  clearPendingVaultInfo,
  hasDropboxToken,
  loadBiometricUnlockInfo,
  loadDropboxAppKey,
  loadPendingVaultInfo,
  loadDropboxTokenInfo,
  saveBiometricUnlockInfo,
  saveDropboxAppKey,
  savePendingVaultInfo,
  saveDropboxTokenInfo,
} from "./lib/storage";
import {
  changeVaultMasterPassword,
  createVaultSession,
  exportVaultRawKey,
  MIN_MASTER_PASSWORD_LENGTH,
  sealVault,
  unlockVault,
  unlockVaultWithRawKey,
  unlockVaultWithKeyContext,
  VAULT_FILE_NAME,
} from "./lib/vault";
import { mergeVaults } from "./lib/vaultMerge";
import { generateTotp, parseTotpInput, type TotpCode } from "./lib/totp";
import type { TotpConfig, VaultCustomField, VaultData, VaultItem, VaultSession } from "./types";

type Notice = {
  kind: "info" | "success" | "error";
  text: string;
} | null;

type SyncStatus = "synced" | "pending" | "saving" | "syncing" | "remote-update" | "offline" | "error";
type SyncMode = "manual" | "auto";

type EntryDraft = {
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  tags: string;
  customFields: VaultCustomField[];
  totpSecret: string;
  totpIssuer: string;
  totpAccount: string;
  totpAlgorithm: "" | TotpConfig["algorithm"];
  totpDigits: string;
  totpPeriod: string;
};

const EMPTY_DRAFT: EntryDraft = {
  title: "",
  username: "",
  password: "",
  url: "",
  notes: "",
  tags: "",
  customFields: [],
  totpSecret: "",
  totpIssuer: "",
  totpAccount: "",
  totpAlgorithm: "",
  totpDigits: "",
  totpPeriod: "",
};

const PRIVACY_HREF = `${import.meta.env.BASE_URL}privacy.html`;
const LOCAL_SAVE_DEBOUNCE_MS = 300;
const AUTO_SYNC_DEBOUNCE_MS = 3000;
const REMOTE_CHECK_INTERVAL_MS = 60_000;
const AUTO_LOCK_MS = 60_000;

export function App() {
  const [appKey, setAppKey] = useState(loadDropboxAppKey);
  const [appKeyDraft, setAppKeyDraft] = useState(appKey);
  const [tokens, setTokens] = useState<DropboxTokenInfo | null>(loadDropboxTokenInfo);
  const [remoteVault, setRemoteVault] = useState<RemoteVault | null>(null);
  const [remoteMissing, setRemoteMissing] = useState(false);
  const [session, setSession] = useState<VaultSession | null>(null);
  const [biometricUnlockInfo, setBiometricUnlockInfo] = useState<BiometricUnlockInfo | null>(loadBiometricUnlockInfo);
  const [baseVaultData, setBaseVaultData] = useState<VaultData | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [dirty, setDirty] = useState(false);
  const [syncStatus, setSyncStatus] = useState<SyncStatus>("synced");
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<Notice>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [unlockPassword, setUnlockPassword] = useState("");
  const [newMasterPassword, setNewMasterPassword] = useState("");
  const [newMasterPasswordConfirm, setNewMasterPasswordConfirm] = useState("");
  const [changedMasterPassword, setChangedMasterPassword] = useState("");
  const [changedMasterPasswordConfirm, setChangedMasterPasswordConfirm] = useState("");
  const [editingId, setEditingId] = useState<string | null>(null);
  const [draft, setDraft] = useState<EntryDraft>(EMPTY_DRAFT);
  const [showPassword, setShowPassword] = useState(false);
  const [showDraftPassword, setShowDraftPassword] = useState(false);
  const [visibleSecrets, setVisibleSecrets] = useState<Record<string, boolean>>({});
  const [visibleDraftFields, setVisibleDraftFields] = useState<Record<string, boolean>>({});
  const [showPasswordHistory, setShowPasswordHistory] = useState(false);
  const [historyVisibility, setHistoryVisibility] = useState<Record<string, boolean>>({});
  const [clockTick, setClockTick] = useState(Date.now());
  const [totpCode, setTotpCode] = useState<TotpCode | null>(null);
  const [passwordOptions, setPasswordOptions] = useState<PasswordGeneratorOptions>(DEFAULT_PASSWORD_OPTIONS);
  const autoLoadAttempted = useRef(false);
  const appKeyRef = useRef(appKey);
  const tokensRef = useRef(tokens);
  const remoteVaultRef = useRef(remoteVault);
  const sessionRef = useRef(session);
  const baseVaultDataRef = useRef(baseVaultData);
  const dirtyRef = useRef(dirty);
  const syncInFlightRef = useRef(false);
  const remoteCheckInFlightRef = useRef(false);
  const autoLockInFlightRef = useRef(false);

  const connected = hasDropboxToken(tokens);
  const biometricAvailable = canUseBiometricUnlock();
  const items = session?.data.items ?? [];
  const visibleItems = useMemo(() => items.filter((item) => !item.deletedAt), [items]);
  const selectedItem = useMemo(
    () => visibleItems.find((item) => item.id === selectedId) ?? null,
    [selectedId, visibleItems],
  );
  const filteredItems = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    if (!normalizedQuery) return visibleItems;
    return visibleItems.filter((item) => {
      const haystack = [
        item.title,
        item.username,
        item.url,
        item.notes,
        item.tags.join(" "),
        item.customFields.map((field) => `${field.label} ${field.value}`).join(" "),
        item.totp ? `${item.totp.issuer} ${item.totp.account}` : "",
      ]
        .join(" ")
        .toLowerCase();
      return haystack.includes(normalizedQuery);
    });
  }, [query, visibleItems]);

  const refreshRemoteVault = useCallback(
    async (tokenOverride?: DropboxTokenInfo | null): Promise<RemoteVault | null> => {
      const activeTokens = tokenOverride ?? tokens;
      if (!appKey || !activeTokens || !hasDropboxToken(activeTokens)) {
        setNotice({ kind: "error", text: "请先填写 Dropbox App key 并完成连接。" });
        return null;
      }

      setBusy("读取 Dropbox");
      try {
        const context = await createDropboxClient(appKey, activeTokens);
        saveDropboxTokenInfo(context.tokens);
        setTokens(context.tokens);
        const downloaded = await downloadRemoteVault(context.dbx);
        setRemoteVault(downloaded);
        setRemoteMissing(downloaded === null);
        setNotice(
          downloaded
            ? { kind: "success", text: `已读取 Dropbox /${VAULT_FILE_NAME}。` }
            : { kind: "info", text: `Dropbox 中还没有 /${VAULT_FILE_NAME}。` },
        );
        return downloaded;
      } catch (error) {
        setNotice({ kind: "error", text: formatDropboxError(error) });
        return null;
      } finally {
        setBusy(null);
      }
    },
    [appKey, tokens],
  );

  useEffect(() => {
    appKeyRef.current = appKey;
  }, [appKey]);

  useEffect(() => {
    tokensRef.current = tokens;
  }, [tokens]);

  useEffect(() => {
    remoteVaultRef.current = remoteVault;
  }, [remoteVault]);

  useEffect(() => {
    sessionRef.current = session;
  }, [session]);

  useEffect(() => {
    baseVaultDataRef.current = baseVaultData;
  }, [baseVaultData]);

  useEffect(() => {
    dirtyRef.current = dirty;
  }, [dirty]);

  useEffect(() => {
    setAppKeyDraft(appKey);
  }, [appKey]);

  useEffect(() => {
    if (!appKey || !hasOAuthRedirect()) return;

    let cancelled = false;
    setBusy("完成 Dropbox 授权");
    completeDropboxAuth(appKey)
      .then(async (nextTokens) => {
        if (cancelled || !nextTokens) return;
        saveDropboxTokenInfo(nextTokens);
        setTokens(nextTokens);
        setNotice({ kind: "success", text: "Dropbox 已连接。" });
        await refreshRemoteVault(nextTokens);
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setNotice({ kind: "error", text: error instanceof Error ? error.message : "Dropbox 授权失败。" });
        }
      })
      .finally(() => {
        if (!cancelled) setBusy(null);
      });

    return () => {
      cancelled = true;
    };
  }, [appKey, refreshRemoteVault]);

  useEffect(() => {
    if (!appKey || !connected || session || autoLoadAttempted.current || hasOAuthRedirect()) return;
    autoLoadAttempted.current = true;
    void refreshRemoteVault();
  }, [appKey, connected, refreshRemoteVault, session]);

  useEffect(() => {
    if (!session) return;
    if (!selectedId && visibleItems[0]) {
      setSelectedId(visibleItems[0].id);
      return;
    }
    if (selectedId && !visibleItems.some((item) => item.id === selectedId)) {
      setSelectedId(visibleItems[0]?.id ?? null);
    }
  }, [selectedId, session, visibleItems]);

  useEffect(() => {
    setShowPassword(false);
    setVisibleSecrets({});
    setVisibleDraftFields({});
    setShowPasswordHistory(false);
    setHistoryVisibility({});
  }, [selectedId]);

  useEffect(() => {
    if (!session) return;
    const intervalId = window.setInterval(() => setClockTick(Date.now()), 1000);
    return () => window.clearInterval(intervalId);
  }, [session]);

  useEffect(() => {
    const totp = selectedItem?.totp;
    if (!totp) {
      setTotpCode(null);
      return;
    }

    let cancelled = false;
    generateTotp(totp, clockTick)
      .then((code) => {
        if (!cancelled) setTotpCode(code);
      })
      .catch(() => {
        if (!cancelled) setTotpCode(null);
      });

    return () => {
      cancelled = true;
    };
  }, [
    clockTick,
    selectedItem?.id,
    selectedItem?.totp?.account,
    selectedItem?.totp?.algorithm,
    selectedItem?.totp?.digits,
    selectedItem?.totp?.issuer,
    selectedItem?.totp?.period,
    selectedItem?.totp?.secret,
  ]);

  useEffect(() => {
    if (!session || !dirty) return;
    setSyncStatus(isOffline() ? "offline" : "pending");

    const localSaveTimer = window.setTimeout(() => {
      void persistLocalPendingVault(session);
    }, LOCAL_SAVE_DEBOUNCE_MS);
    const autoSyncTimer = window.setTimeout(() => {
      void syncVault("auto");
    }, AUTO_SYNC_DEBOUNCE_MS);

    return () => {
      window.clearTimeout(localSaveTimer);
      window.clearTimeout(autoSyncTimer);
    };
  }, [dirty, session]);

  useEffect(() => {
    if (!session || !connected) return;

    void checkRemoteForUpdates("auto");

    const handleVisibilityChange = () => {
      if (document.visibilityState === "visible") {
        void checkRemoteForUpdates("auto");
      }
    };
    const handleOnline = () => {
      if (dirtyRef.current) {
        void syncVault("auto");
      } else {
        void checkRemoteForUpdates("auto");
      }
    };
    const intervalId = window.setInterval(() => {
      if (document.visibilityState === "visible") {
        void checkRemoteForUpdates("auto");
      }
    }, REMOTE_CHECK_INTERVAL_MS);

    document.addEventListener("visibilitychange", handleVisibilityChange);
    window.addEventListener("online", handleOnline);
    return () => {
      document.removeEventListener("visibilitychange", handleVisibilityChange);
      window.removeEventListener("online", handleOnline);
      window.clearInterval(intervalId);
    };
  }, [connected, session?.keyContext]);

  useEffect(() => {
    if (!session) return;

    let lockTimerId: number | null = null;
    const resetAutoLockTimer = () => {
      if (lockTimerId !== null) {
        window.clearTimeout(lockTimerId);
      }
      lockTimerId = window.setTimeout(() => {
        void lockVault({
          confirmDirty: false,
          noticeText: "超过 60 秒无操作，密码库已自动锁定。",
        });
      }, AUTO_LOCK_MS);
    };
    const handleVisibilityChange = () => {
      if (document.visibilityState === "hidden") {
        void lockVault({
          confirmDirty: false,
          noticeText: "已切出页面，密码库已自动锁定。",
        });
      } else {
        resetAutoLockTimer();
      }
    };

    resetAutoLockTimer();
    document.addEventListener("visibilitychange", handleVisibilityChange);
    window.addEventListener("pointerdown", resetAutoLockTimer, { passive: true });
    window.addEventListener("keydown", resetAutoLockTimer);
    window.addEventListener("touchstart", resetAutoLockTimer, { passive: true });
    window.addEventListener("scroll", resetAutoLockTimer, { passive: true });

    return () => {
      if (lockTimerId !== null) {
        window.clearTimeout(lockTimerId);
      }
      document.removeEventListener("visibilitychange", handleVisibilityChange);
      window.removeEventListener("pointerdown", resetAutoLockTimer);
      window.removeEventListener("keydown", resetAutoLockTimer);
      window.removeEventListener("touchstart", resetAutoLockTimer);
      window.removeEventListener("scroll", resetAutoLockTimer);
    };
  }, [session]);

  function markVaultDirty() {
    dirtyRef.current = true;
    setDirty(true);
    setSyncStatus(isOffline() ? "offline" : "pending");
  }

  async function persistLocalPendingVault(sessionSnapshot: VaultSession) {
    if (!dirtyRef.current) return;
    setSyncStatus("saving");
    try {
      const sealed = await sealVault(sessionSnapshot);
      if (!dirtyRef.current || sessionRef.current !== sessionSnapshot) return;
      savePendingVaultInfo({
        text: sealed.text,
        savedAt: new Date().toISOString(),
        remoteRev: remoteVaultRef.current?.rev ?? null,
      });
      setSyncStatus(isOffline() ? "offline" : "pending");
    } catch (error) {
      setSyncStatus("error");
      setNotice({ kind: "error", text: error instanceof Error ? error.message : "本地加密保存失败。" });
    }
  }

  async function syncVault(mode: SyncMode) {
    const currentSession = sessionRef.current;
    if (!currentSession) return;
    if (syncInFlightRef.current) return;
    if (isOffline()) {
      setSyncStatus("offline");
      if (mode === "manual") {
        setNotice({ kind: "info", text: "当前离线，已保留本地加密待同步副本。" });
      }
      return;
    }

    syncInFlightRef.current = true;
    setSyncStatus("syncing");
    if (mode === "manual") {
      setBusy("加密并同步");
    }

    try {
      const context = await requireDropboxClient();
      const sealed = await sealVault(currentSession);
      try {
        const uploaded = await uploadRemoteVault(context.dbx, sealed.text, remoteVaultRef.current?.rev ?? null);
        const applied = applySyncedVault(currentSession, sealed.data, uploaded);
        if (mode === "manual") {
          setNotice({
            kind: "success",
            text: applied ? "已同步到 Dropbox。" : "已上传当前快照，新的本地修改将继续自动同步。",
          });
        }
      } catch (error) {
        if (!isDropboxConflict(error)) {
          throw error;
        }
        const downloaded = await downloadRemoteVault(context.dbx);
        if (!downloaded) {
          const uploaded = await uploadRemoteVault(context.dbx, sealed.text, null);
          const applied = applySyncedVault(currentSession, sealed.data, uploaded);
          if (mode === "manual") {
            setNotice({
              kind: "success",
              text: applied ? "远端文件不存在，已重新创建 vault.enc。" : "已重新创建远端文件，新的本地修改将继续自动同步。",
            });
          }
          return;
        }

        const remoteSession = await unlockVaultWithKeyContext(downloaded.text, currentSession.keyContext);
        const merged = mergeVaults(baseVaultDataRef.current, sealed.data, remoteSession.data);
        const mergedSession: VaultSession = {
          ...currentSession,
          data: merged.data,
        };
        const mergedSealed = await sealVault(mergedSession);
        const uploaded = await uploadRemoteVault(context.dbx, mergedSealed.text, downloaded.rev);
        const applied = applySyncedVault(mergedSession, mergedSealed.data, uploaded);
        setNotice({
          kind: "success",
          text:
            !applied
              ? "已上传合并结果，新的本地修改将继续自动同步。"
              : merged.conflicts > 0
              ? `已自动合并并同步。${merged.conflicts} 处字段冲突保留本地版本。`
              : "已自动合并远端更新并同步。",
        });
      }
    } catch (error) {
      setSyncStatus(isOffline() ? "offline" : "error");
      setNotice({ kind: "error", text: formatDropboxError(error) });
    } finally {
      syncInFlightRef.current = false;
      if (mode === "manual") {
        setBusy(null);
      }
    }
  }

  async function checkRemoteForUpdates(mode: SyncMode) {
    const currentSession = sessionRef.current;
    if (!currentSession || !hasDropboxToken(tokensRef.current)) return;
    if (syncInFlightRef.current || remoteCheckInFlightRef.current) return;
    if (isOffline()) {
      if (dirtyRef.current) {
        setSyncStatus("offline");
      }
      return;
    }

    let shouldSyncAfterCheck = false;
    remoteCheckInFlightRef.current = true;
    try {
      const context = await requireDropboxClient();
      const metadata = await getRemoteVaultMetadata(context.dbx);
      if (!metadata) {
        setRemoteVault(null);
        setRemoteMissing(true);
        if (dirtyRef.current) {
          shouldSyncAfterCheck = true;
          setSyncStatus("pending");
        } else {
          setSyncStatus("synced");
        }
        return;
      }

      setRemoteMissing(false);
      if (remoteVaultRef.current?.rev === metadata.rev) {
        if (!dirtyRef.current) {
          setSyncStatus("synced");
        }
        if (mode === "manual") {
          setNotice({ kind: "success", text: "Dropbox 已是最新版本。" });
        }
        return;
      }

      setSyncStatus("remote-update");
      if (dirtyRef.current) {
        shouldSyncAfterCheck = true;
        return;
      }

      const downloaded = await downloadRemoteVault(context.dbx);
      if (!downloaded) {
        setRemoteVault(null);
        setRemoteMissing(true);
        return;
      }
      const nextSession = await unlockVaultWithKeyContext(downloaded.text, currentSession.keyContext);
      applyRemoteVault(nextSession, downloaded);
      setNotice({
        kind: "success",
        text: mode === "manual" ? "已加载远端最新数据。" : "已自动加载 Dropbox 最新数据。",
      });
    } catch (error) {
      setSyncStatus("error");
      setNotice({ kind: "error", text: formatDropboxError(error) });
    } finally {
      remoteCheckInFlightRef.current = false;
      if (shouldSyncAfterCheck) {
        void syncVault(mode);
      }
    }
  }

  function applySyncedVault(sourceSession: VaultSession, data: VaultData, uploaded: RemoteVault): boolean {
    setRemoteVault(uploaded);
    setRemoteMissing(false);
    setBaseVaultData(data);
    const latestSession = sessionRef.current;
    if (!latestSession) {
      dirtyRef.current = false;
      setDirty(false);
      setSyncStatus("synced");
      clearPendingVaultInfo();
      return true;
    }
    if (latestSession !== sourceSession) {
      setSyncStatus(isOffline() ? "offline" : "pending");
      return false;
    }
    setSession({ ...sourceSession, data });
    dirtyRef.current = false;
    setDirty(false);
    setSyncStatus("synced");
    clearPendingVaultInfo();
    return true;
  }

  function applyRemoteVault(nextSession: VaultSession, downloaded: RemoteVault) {
    setRemoteVault(downloaded);
    setRemoteMissing(false);
    setBaseVaultData(nextSession.data);
    setSession(nextSession);
    dirtyRef.current = false;
    setDirty(false);
    setSyncStatus("synced");
    clearPendingVaultInfo();
    setSelectedId(nextSession.data.items.find((item) => !item.deletedAt)?.id ?? null);
  }

  async function restorePendingVaultIfNewer(remoteSession: VaultSession): Promise<VaultSession | null> {
    const pending = loadPendingVaultInfo();
    if (!pending) {
      return null;
    }

    try {
      const pendingSession = await unlockVaultWithKeyContext(pending.text, remoteSession.keyContext);
      const pendingUpdatedAt = Date.parse(pendingSession.data.meta.updatedAt);
      const remoteUpdatedAt = Date.parse(remoteSession.data.meta.updatedAt);
      const sameRemoteBase = pending.remoteRev !== null && pending.remoteRev === remoteVaultRef.current?.rev;
      if (
        pendingUpdatedAt > remoteUpdatedAt ||
        (sameRemoteBase && !vaultDataEqual(pendingSession.data, remoteSession.data))
      ) {
        return pendingSession;
      }
      clearPendingVaultInfo();
      return null;
    } catch {
      return null;
    }
  }

  async function unlockPendingVaultWithPassword(masterPassword: string): Promise<VaultSession | null> {
    const pending = loadPendingVaultInfo();
    if (!pending) {
      return null;
    }
    try {
      return await unlockVault(pending.text, masterPassword);
    } catch {
      return null;
    }
  }

  function applyUnlockedVault(remoteSession: VaultSession, pendingSession: VaultSession | null, successText: string) {
    const nextSession = pendingSession ?? remoteSession;
    setBaseVaultData(remoteSession.data);
    setSession(nextSession);
    setUnlockPassword("");
    setDirty(Boolean(pendingSession));
    dirtyRef.current = Boolean(pendingSession);
    setSyncStatus(pendingSession ? (isOffline() ? "offline" : "pending") : "synced");
    setSelectedId(nextSession.data.items.find((item) => !item.deletedAt)?.id ?? null);
    setNotice({
      kind: "success",
      text: pendingSession ? "已解锁，并恢复本机未同步修改。" : successText,
    });
  }

  async function handleConnectDropbox() {
    const nextAppKey = appKeyDraft.trim();
    if (!nextAppKey) {
      setNotice({ kind: "error", text: "请输入 Dropbox App key。" });
      return;
    }
    saveDropboxAppKey(nextAppKey);
    setAppKey(nextAppKey);
    setBusy("跳转 Dropbox");
    try {
      await startDropboxAuth(nextAppKey);
    } catch (error) {
      setBusy(null);
      setNotice({ kind: "error", text: error instanceof Error ? error.message : "无法启动 Dropbox 授权。" });
    }
  }

  function handleSaveSettings() {
    const nextAppKey = appKeyDraft.trim();
    saveDropboxAppKey(nextAppKey);
    const effectiveAppKey = loadDropboxAppKey();
    if (effectiveAppKey !== appKey) {
      saveDropboxTokenInfo(null);
      setTokens(null);
      setRemoteVault(null);
      setRemoteMissing(false);
      setSession(null);
      setBaseVaultData(null);
      dirtyRef.current = false;
      setDirty(false);
      setSyncStatus("synced");
      autoLoadAttempted.current = false;
    }
    setAppKey(effectiveAppKey);
    setSettingsOpen(false);
    setNotice({ kind: "success", text: "设置已保存。" });
  }

  function handleForgetDropbox() {
    saveDropboxTokenInfo(null);
    setTokens(null);
    setRemoteVault(null);
    setRemoteMissing(false);
    setSession(null);
    setBaseVaultData(null);
    dirtyRef.current = false;
    setDirty(false);
    setSyncStatus("synced");
    autoLoadAttempted.current = false;
    setNotice({ kind: "info", text: "已移除本机 Dropbox token。" });
  }

  async function lockVault({
    confirmDirty,
    noticeText,
  }: {
    confirmDirty: boolean;
    noticeText: string;
  }) {
    if (autoLockInFlightRef.current) {
      return;
    }

    autoLockInFlightRef.current = true;
    try {
      if (confirmDirty && dirtyRef.current && !window.confirm("有未同步修改。仍要锁定密码库吗？")) {
        return;
      }
      if (dirtyRef.current && sessionRef.current) {
        await persistLocalPendingVault(sessionRef.current);
      }
      setSession(null);
      setSelectedId(null);
      setEditingId(null);
      setUnlockPassword("");
      setChangedMasterPassword("");
      setChangedMasterPasswordConfirm("");
      setBaseVaultData(null);
      dirtyRef.current = false;
      setDirty(false);
      setSyncStatus("synced");
      setNotice({ kind: "info", text: noticeText });
    } finally {
      autoLockInFlightRef.current = false;
    }
  }

  async function handleLockVault() {
    await lockVault({
      confirmDirty: true,
      noticeText: "密码库已锁定。",
    });
  }

  async function handleUnlock(event: FormEvent) {
    event.preventDefault();
    if (!remoteVault) {
      setNotice({ kind: "error", text: "请先从 Dropbox 读取 vault.enc。" });
      return;
    }
    setBusy("解锁密码库");
    try {
      const remoteSession = await unlockVault(remoteVault.text, unlockPassword);
      const pendingSession = await restorePendingVaultIfNewer(remoteSession);
      applyUnlockedVault(remoteSession, pendingSession, "密码库已解锁。");
    } catch (error) {
      const pendingSession = await unlockPendingVaultWithPassword(unlockPassword);
      if (pendingSession) {
        setBaseVaultData(null);
        setSession(pendingSession);
        setUnlockPassword("");
        dirtyRef.current = true;
        setDirty(true);
        setSyncStatus(isOffline() ? "offline" : "pending");
        setSelectedId(pendingSession.data.items.find((item) => !item.deletedAt)?.id ?? null);
        setNotice({ kind: "success", text: "已从本机加密待同步副本恢复密码库。" });
      } else {
        setNotice({ kind: "error", text: error instanceof Error ? error.message : "解锁失败。" });
      }
    } finally {
      setBusy(null);
    }
  }

  async function handleBiometricUnlock() {
    if (!remoteVault) {
      setNotice({ kind: "error", text: "请先从 Dropbox 读取 vault.enc。" });
      return;
    }
    if (!biometricUnlockInfo) {
      setNotice({ kind: "error", text: "这台设备还没有启用指纹/面容解锁。" });
      return;
    }

    setBusy("验证指纹/面容");
    let rawKey: Uint8Array | null = null;
    try {
      rawKey = await unwrapBiometricVaultKey(biometricUnlockInfo);
      const remoteSession = await unlockVaultWithRawKey(remoteVault.text, rawKey);
      const pendingSession = await restorePendingVaultIfNewer(remoteSession);
      applyUnlockedVault(remoteSession, pendingSession, "已使用指纹/面容解锁。");
    } catch (error) {
      setNotice({ kind: "error", text: error instanceof Error ? error.message : "指纹/面容解锁失败。" });
    } finally {
      rawKey?.fill(0);
      setBusy(null);
    }
  }

  async function handleEnableBiometricUnlock() {
    if (!session) return;
    if (!biometricAvailable) {
      setNotice({ kind: "error", text: "当前浏览器或访问地址不支持 WebAuthn。请使用 HTTPS 或 localhost。" });
      return;
    }

    setBusy("启用指纹/面容");
    let rawKey: Uint8Array | null = null;
    try {
      rawKey = await exportVaultRawKey(session);
      const info = await createBiometricUnlockInfo(rawKey, session.keyContext);
      saveBiometricUnlockInfo(info);
      setBiometricUnlockInfo(info);
      setNotice({ kind: "success", text: "已为这台设备启用指纹/面容解锁。" });
    } catch (error) {
      setNotice({ kind: "error", text: error instanceof Error ? error.message : "启用指纹/面容解锁失败。" });
    } finally {
      rawKey?.fill(0);
      setBusy(null);
    }
  }

  function handleDisableBiometricUnlock() {
    clearBiometricUnlockInfo();
    setBiometricUnlockInfo(null);
    setNotice({ kind: "info", text: "已停用这台设备的指纹/面容解锁。" });
  }

  async function handleCreateVault(event: FormEvent) {
    event.preventDefault();
    if (!connected) {
      setNotice({ kind: "error", text: "请先连接 Dropbox。" });
      return;
    }
    if (newMasterPassword.length < MIN_MASTER_PASSWORD_LENGTH) {
      setNotice({ kind: "error", text: `主密码至少 ${MIN_MASTER_PASSWORD_LENGTH} 个字符。` });
      return;
    }
    if (newMasterPassword !== newMasterPasswordConfirm) {
      setNotice({ kind: "error", text: "两次输入的主密码不一致。" });
      return;
    }

    setBusy("创建密码库");
    try {
      const nextSession = await createVaultSession(newMasterPassword);
      const sealed = await sealVault(nextSession);
      const context = await requireDropboxClient();
      const uploaded = await uploadRemoteVault(context.dbx, sealed.text, null);
      setRemoteVault(uploaded);
      setRemoteMissing(false);
      setBaseVaultData(sealed.data);
      setSession({ ...nextSession, data: sealed.data });
      dirtyRef.current = false;
      setDirty(false);
      setSyncStatus("synced");
      clearPendingVaultInfo();
      setNewMasterPassword("");
      setNewMasterPasswordConfirm("");
      setNotice({ kind: "success", text: `已创建并上传 /${VAULT_FILE_NAME}。` });
    } catch (error) {
      setNotice({ kind: "error", text: formatDropboxError(error) });
    } finally {
      setBusy(null);
    }
  }

  async function handleSyncVault() {
    await syncVault("manual");
  }

  async function handleChangeMasterPassword(event: FormEvent) {
    event.preventDefault();
    if (!session) return;
    if (changedMasterPassword.length < MIN_MASTER_PASSWORD_LENGTH) {
      setNotice({ kind: "error", text: `新主密码至少 ${MIN_MASTER_PASSWORD_LENGTH} 个字符。` });
      return;
    }
    if (changedMasterPassword !== changedMasterPasswordConfirm) {
      setNotice({ kind: "error", text: "两次输入的新主密码不一致。" });
      return;
    }

    setBusy("修改主密码");
    try {
      const nextSession = await changeVaultMasterPassword(session, changedMasterPassword);
      setSession(nextSession);
      markVaultDirty();
      clearBiometricUnlockInfo();
      setBiometricUnlockInfo(null);
      setChangedMasterPassword("");
      setChangedMasterPasswordConfirm("");
      setNotice({ kind: "success", text: "主密码已修改，将自动同步到 Dropbox。请重新启用指纹/面容解锁。" });
    } catch (error) {
      setNotice({ kind: "error", text: error instanceof Error ? error.message : "主密码修改失败。" });
    } finally {
      setBusy(null);
    }
  }

  async function handlePullRemoteIntoSession() {
    if (!session) return;
    await checkRemoteForUpdates("manual");
  }

  async function handleExportEncrypted() {
    const encryptedText = session ? (await sealVault(session)).text : remoteVault?.text;
    if (!encryptedText) {
      setNotice({ kind: "error", text: "没有可导出的 vault.enc。" });
      return;
    }
    const url = URL.createObjectURL(new Blob([encryptedText], { type: "application/octet-stream" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = VAULT_FILE_NAME;
    link.click();
    URL.revokeObjectURL(url);
  }

  function handleNewItem() {
    setEditingId(null);
    setDraft({
      ...EMPTY_DRAFT,
      password: generatePassword(passwordOptions),
      customFields: [],
    });
    setShowDraftPassword(true);
    setVisibleDraftFields({});
  }

  function handleEditItem(item: VaultItem) {
    setEditingId(item.id);
    setDraft(itemToDraft(item));
    setShowDraftPassword(false);
    setVisibleDraftFields({});
  }

  function handleCancelEdit() {
    setEditingId(null);
    setDraft(EMPTY_DRAFT);
    setShowDraftPassword(false);
    setVisibleDraftFields({});
  }

  function handleSaveItem(event: FormEvent) {
    event.preventDefault();
    if (!session) return;

    const normalizedTitle = draft.title.trim();
    if (!normalizedTitle) {
      setNotice({ kind: "error", text: "名称不能为空。" });
      return;
    }
    if (!draft.password) {
      setNotice({ kind: "error", text: "密码不能为空。" });
      return;
    }

    const now = new Date().toISOString();
    const existingItem = editingId ? session.data.items.find((item) => item.id === editingId) ?? null : null;
    let totp: TotpConfig | null;
    try {
      totp = parseTotpDraft(draft);
    } catch (error) {
      setNotice({ kind: "error", text: error instanceof Error ? error.message : "一次性密码配置无效。" });
      return;
    }
    const passwordHistory =
      existingItem && existingItem.password !== draft.password
        ? [
            {
              id: randomId("history"),
              password: existingItem.password,
              changedAt: now,
            },
            ...existingItem.passwordHistory,
          ].slice(0, 50)
        : existingItem?.passwordHistory ?? [];
    const nextItem: VaultItem = {
      id: editingId ?? randomId("entry"),
      title: normalizedTitle,
      username: draft.username.trim(),
      password: draft.password,
      url: draft.url.trim(),
      notes: draft.notes,
      tags: parseTags(draft.tags),
      customFields: normalizeDraftCustomFields(draft.customFields),
      passwordHistory,
      totp,
      createdAt: existingItem?.createdAt ?? now,
      updatedAt: now,
    };

    setSession((previous) => {
      if (!previous) return previous;
      const nextItems = editingId
        ? previous.data.items.map((item) => (item.id === editingId ? nextItem : item))
        : [nextItem, ...previous.data.items];
      return {
        ...previous,
        data: {
          ...previous.data,
          meta: {
            ...previous.data.meta,
            updatedAt: now,
          },
          items: nextItems,
        },
      };
    });
    setSelectedId(nextItem.id);
    setEditingId(null);
    setDraft(EMPTY_DRAFT);
    markVaultDirty();
    setNotice({ kind: "success", text: editingId ? "条目已更新。" : "条目已添加。" });
  }

  function handleDeleteItem(item: VaultItem) {
    if (!window.confirm(`删除 ${item.title}？`)) return;
    const now = new Date().toISOString();
    setSession((previous) => {
      if (!previous) return previous;
      return {
        ...previous,
        data: {
          ...previous.data,
          meta: {
            ...previous.data.meta,
            updatedAt: now,
          },
          items: previous.data.items.map((candidate) =>
            candidate.id === item.id
              ? {
                  ...candidate,
                  updatedAt: now,
                  deletedAt: now,
                }
              : candidate,
          ),
        },
      };
    });
    setSelectedId(visibleItems.find((candidate) => candidate.id !== item.id)?.id ?? null);
    markVaultDirty();
    setNotice({ kind: "info", text: "条目已删除。" });
  }

  function handleAddCustomField(kind: VaultCustomField["kind"]) {
    setDraft((previous) => ({
      ...previous,
      customFields: [
        ...previous.customFields,
        {
          id: randomId("field"),
          label: "",
          value: "",
          kind,
        },
      ],
    }));
  }

  function handleUpdateCustomField(id: string, patch: Partial<VaultCustomField>) {
    setDraft((previous) => ({
      ...previous,
      customFields: previous.customFields.map((field) => (field.id === id ? { ...field, ...patch } : field)),
    }));
  }

  function handleGenerateCustomField(id: string) {
    handleUpdateCustomField(id, { value: generatePassword(passwordOptions) });
    setVisibleDraftFields((previous) => ({ ...previous, [id]: true }));
  }

  function handleRemoveCustomField(id: string) {
    setDraft((previous) => ({
      ...previous,
      customFields: previous.customFields.filter((field) => field.id !== id),
    }));
    setVisibleDraftFields((previous) => {
      const next = { ...previous };
      delete next[id];
      return next;
    });
  }

  function toggleSecretVisibility(id: string) {
    setVisibleSecrets((previous) => ({
      ...previous,
      [id]: !previous[id],
    }));
  }

  function toggleHistoryVisibility(id: string) {
    setHistoryVisibility((previous) => ({
      ...previous,
      [id]: !previous[id],
    }));
  }

  function toggleDraftFieldVisibility(id: string) {
    setVisibleDraftFields((previous) => ({
      ...previous,
      [id]: !previous[id],
    }));
  }

  async function copyToClipboard(value: string, label: string) {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      setNotice({ kind: "success", text: `${label}已复制。` });
    } catch {
      setNotice({ kind: "error", text: "浏览器拒绝剪贴板写入。" });
    }
  }

  async function requireDropboxClient() {
    const activeAppKey = appKeyRef.current;
    const activeTokens = tokensRef.current;
    if (!activeAppKey || !activeTokens || !hasDropboxToken(activeTokens)) {
      throw new Error("请先连接 Dropbox。");
    }
    const context = await createDropboxClient(activeAppKey, activeTokens);
    saveDropboxTokenInfo(context.tokens);
    tokensRef.current = context.tokens;
    setTokens(context.tokens);
    return context;
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <span className="brand-icon">
            <ShieldCheck size={22} />
          </span>
          <div>
            <h1>Easy Pass</h1>
            <p>{session ? `${visibleItems.length} 个条目` : "端到端加密密码库"}</p>
          </div>
        </div>

        <div className="topbar-actions">
          <span className={`sync-pill ${connected ? "connected" : ""}`}>
            {connected ? <Cloud size={16} /> : <CloudOff size={16} />}
            {connected ? "Dropbox" : "未连接"}
          </span>
          {session && (
            <>
              <span className={`sync-pill sync-state ${syncStatus}`}>
                {syncStatus === "syncing" || syncStatus === "saving" ? (
                  <RefreshCw className="spin" size={16} />
                ) : syncStatus === "offline" ? (
                  <CloudOff size={16} />
                ) : (
                  <Check size={16} />
                )}
                {getSyncStatusLabel(syncStatus, dirty)}
              </span>
              <button className="icon-button" title="拉取远端" onClick={handlePullRemoteIntoSession} disabled={Boolean(busy)}>
                <Download size={18} />
              </button>
              <button
                className="primary-button"
                onClick={handleSyncVault}
                disabled={Boolean(busy) || syncStatus === "syncing" || (!dirty && syncStatus === "synced")}
                title="同步到 Dropbox"
              >
                <Save size={17} />
                {getSyncButtonLabel(syncStatus, dirty)}
              </button>
              <button className="icon-button" title="锁定" onClick={() => void handleLockVault()}>
                <Lock size={18} />
              </button>
            </>
          )}
          <button className="icon-button" title="设置" onClick={() => setSettingsOpen(true)}>
            <Settings size={18} />
          </button>
        </div>
      </header>

      {notice && (
        <div className={`notice ${notice.kind}`}>
          <span>{notice.text}</span>
          <button title="关闭" onClick={() => setNotice(null)}>
            <X size={16} />
          </button>
        </div>
      )}

      <main className="main-surface">{session ? renderUnlocked() : renderLocked()}</main>
      <footer className="app-footer">
        <a href={PRIVACY_HREF}>隐私协议</a>
      </footer>

      {settingsOpen && renderSettings()}
      {busy && (
        <div className="busy-overlay">
          <div className="busy-box">
            <RefreshCw className="spin" size={20} />
            <span>{busy}</span>
          </div>
        </div>
      )}
    </div>
  );

  function renderLocked() {
    if (!appKey) {
      return (
        <section className="locked-panel">
          <div className="panel-heading">
            <KeyRound size={24} />
            <h2>配置 Dropbox</h2>
          </div>
          <label className="field">
            <span>App key</span>
            <input
              value={appKeyDraft}
              onChange={(event) => setAppKeyDraft(event.target.value)}
              placeholder="Dropbox App key"
              autoComplete="off"
            />
          </label>
          <p className="muted">Redirect URI: {getDropboxRedirectUri()}</p>
          <button className="primary-button wide" onClick={handleConnectDropbox} disabled={Boolean(busy)}>
            <Cloud size={17} />
            连接 Dropbox
          </button>
        </section>
      );
    }

    if (!connected) {
      return (
        <section className="locked-panel">
          <div className="panel-heading">
            <CloudOff size={24} />
            <h2>连接 Dropbox</h2>
          </div>
          <p className="muted">App key 已保存。Redirect URI: {getDropboxRedirectUri()}</p>
          <button className="primary-button wide" onClick={handleConnectDropbox} disabled={Boolean(busy)}>
            <Cloud size={17} />
            连接 Dropbox
          </button>
        </section>
      );
    }

    if (remoteMissing) {
      return (
        <section className="locked-panel">
          <div className="panel-heading">
            <KeyRound size={24} />
            <h2>创建密码库</h2>
          </div>
          <form className="stack" onSubmit={handleCreateVault}>
            <label className="field">
              <span>主密码</span>
              <input
                type="password"
                value={newMasterPassword}
                onChange={(event) => setNewMasterPassword(event.target.value)}
                autoComplete="new-password"
                minLength={MIN_MASTER_PASSWORD_LENGTH}
              />
            </label>
            <label className="field">
              <span>确认主密码</span>
              <input
                type="password"
                value={newMasterPasswordConfirm}
                onChange={(event) => setNewMasterPasswordConfirm(event.target.value)}
                autoComplete="new-password"
                minLength={MIN_MASTER_PASSWORD_LENGTH}
              />
            </label>
            <p className="muted">主密码至少 {MIN_MASTER_PASSWORD_LENGTH} 个字符。</p>
            <button className="primary-button wide" type="submit" disabled={Boolean(busy)}>
              <Check size={17} />
              创建 vault.enc
            </button>
          </form>
        </section>
      );
    }

    if (!remoteVault) {
      return (
        <section className="locked-panel">
          <div className="panel-heading">
            <Cloud size={24} />
            <h2>读取密码库</h2>
          </div>
          <p className="muted">Dropbox 已连接，密码库文件路径为 /{VAULT_FILE_NAME}。</p>
          <button className="primary-button wide" onClick={() => void refreshRemoteVault()} disabled={Boolean(busy)}>
            <RefreshCw size={17} />
            读取 Dropbox
          </button>
        </section>
      );
    }

    return (
      <section className="locked-panel">
        <div className="panel-heading">
          <Lock size={24} />
          <h2>解锁密码库</h2>
        </div>
        <p className="muted">
          /{VAULT_FILE_NAME} · {formatBytes(remoteVault.size)} · {formatDate(remoteVault.serverModified)}
        </p>
        <form className="stack" onSubmit={handleUnlock}>
          <label className="field">
            <span>主密码</span>
            <input
              type="password"
              value={unlockPassword}
              onChange={(event) => setUnlockPassword(event.target.value)}
              autoComplete="current-password"
              autoFocus
            />
          </label>
          <button className="primary-button wide" type="submit" disabled={Boolean(busy)}>
            <KeyRound size={17} />
            解锁
          </button>
        </form>
        {biometricUnlockInfo && (
          <button
            className="ghost-button wide biometric-unlock-button"
            type="button"
            onClick={() => void handleBiometricUnlock()}
            disabled={Boolean(busy) || !biometricAvailable}
          >
            <Fingerprint size={17} />
            指纹/面容解锁
          </button>
        )}
      </section>
    );
  }

  function renderUnlocked() {
    return (
      <div className="vault-layout">
        <aside className="vault-sidebar">
          <div className="sidebar-tools">
            <label className="search-box">
              <Search size={17} />
              <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索" />
            </label>
            <button className="primary-button compact" onClick={handleNewItem}>
              <Plus size={17} />
              新增
            </button>
          </div>

          <div className="vault-list">
            {filteredItems.map((item) => (
              <button
                key={item.id}
                className={`vault-list-item ${item.id === selectedId ? "selected" : ""}`}
                onClick={() => {
                  setSelectedId(item.id);
                  handleCancelEdit();
                }}
              >
                <span className="item-title">{item.title}</span>
                <span className="item-subtitle">{item.username || item.url || "未填写账号"}</span>
              </button>
            ))}
            {filteredItems.length === 0 && <div className="empty-list">没有匹配条目</div>}
          </div>
        </aside>

        <section className="detail-pane">
          {draft !== EMPTY_DRAFT || editingId ? renderEditor() : selectedItem ? renderItemDetail(selectedItem) : renderEmptyDetail()}
        </section>
      </div>
    );
  }

  function renderItemDetail(item: VaultItem) {
    return (
      <div className="detail-content">
        <div className="detail-header">
          <div>
            <h2>{item.title}</h2>
            <p>{item.updatedAt ? `更新于 ${formatDate(item.updatedAt)}` : ""}</p>
          </div>
          <div className="button-row">
            <button className="icon-button" title="编辑" onClick={() => handleEditItem(item)}>
              <Pencil size={18} />
            </button>
            <button className="icon-button danger" title="删除" onClick={() => handleDeleteItem(item)}>
              <Trash2 size={18} />
            </button>
          </div>
        </div>

        <div className="detail-grid">
          <div className="detail-label">账号</div>
          <div className="detail-value">
            <span>{item.username || "未填写"}</span>
            {item.username && (
              <button className="icon-button small" title="复制账号" onClick={() => void copyToClipboard(item.username, "账号")}>
                <Copy size={15} />
              </button>
            )}
          </div>

          <div className="detail-label">密码</div>
          <div className="detail-value password-value">
            <span>{showPassword ? item.password : "••••••••••••"}</span>
            <div className="password-actions">
              <button className="icon-button small" title={showPassword ? "隐藏密码" : "显示密码"} onClick={() => setShowPassword(!showPassword)}>
                {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
              </button>
              <button className="icon-button small" title="复制密码" onClick={() => void copyToClipboard(item.password, "密码")}>
                <Copy size={15} />
              </button>
            </div>
          </div>

          {item.totp && (
            <>
              <div className="detail-label">一次性密码</div>
              <div className="totp-card">
                <div>
                  <div className="totp-code">{totpCode ? formatTotpCode(totpCode.code) : "------"}</div>
                  <div className="muted">
                    {[item.totp.issuer, item.totp.account].filter(Boolean).join(" · ") || "TOTP"}
                  </div>
                </div>
                <div className="totp-actions">
                  <span>{totpCode?.secondsRemaining ?? item.totp.period}s</span>
                  <button
                    className="icon-button small"
                    title="复制一次性密码"
                    onClick={() => totpCode && void copyToClipboard(totpCode.code, "一次性密码")}
                  >
                    <Copy size={15} />
                  </button>
                </div>
                <div className="totp-progress">
                  <span
                    style={{
                      width: `${totpCode ? (totpCode.secondsRemaining / totpCode.period) * 100 : 0}%`,
                    }}
                  />
                </div>
              </div>
            </>
          )}

          <div className="detail-label">网址</div>
          <div className="detail-value">
            {item.url ? (
              <a href={normalizeUrl(item.url)} target="_blank" rel="noreferrer">
                {item.url}
              </a>
            ) : (
              <span>未填写</span>
            )}
          </div>

          {item.customFields.map((field) => (
            <CustomFieldDetail
              key={field.id}
              field={field}
              visible={field.kind === "plain" || Boolean(visibleSecrets[field.id])}
              onToggle={() => toggleSecretVisibility(field.id)}
              onCopy={() => void copyToClipboard(field.value, field.label || "字段")}
            />
          ))}

          <div className="detail-label">标签</div>
          <div className="tag-row">
            {item.tags.length ? item.tags.map((tag) => <span key={tag}>{tag}</span>) : <span className="muted">未填写</span>}
          </div>

          <div className="detail-label">备注</div>
          <div className="notes-value">{item.notes || "未填写"}</div>

          <div className="detail-label">历史密码</div>
          <div className="history-list">
            {item.passwordHistory.length ? (
              <>
                <button className="ghost-button" type="button" onClick={() => setShowPasswordHistory(!showPasswordHistory)}>
                  <History size={16} />
                  {showPasswordHistory ? "隐藏" : "查看"} {item.passwordHistory.length} 条
                </button>
                {showPasswordHistory &&
                  item.passwordHistory.map((historyItem) => (
                    <div className="history-row" key={historyItem.id}>
                      <span className="history-date">{formatDate(historyItem.changedAt)}</span>
                      <span className="history-password">
                        {historyVisibility[historyItem.id] ? historyItem.password : "••••••••••••"}
                      </span>
                      <button
                        className="icon-button small"
                        title={historyVisibility[historyItem.id] ? "隐藏历史密码" : "显示历史密码"}
                        onClick={() => toggleHistoryVisibility(historyItem.id)}
                      >
                        {historyVisibility[historyItem.id] ? <EyeOff size={15} /> : <Eye size={15} />}
                      </button>
                      <button
                        className="icon-button small"
                        title="复制历史密码"
                        onClick={() => void copyToClipboard(historyItem.password, "历史密码")}
                      >
                        <Copy size={15} />
                      </button>
                    </div>
                  ))}
              </>
            ) : (
              <span className="muted">暂无历史</span>
            )}
          </div>
        </div>
      </div>
    );
  }

  function renderEditor() {
    return (
      <form className="editor-form" onSubmit={handleSaveItem}>
        <div className="detail-header">
          <div>
            <h2>{editingId ? "编辑条目" : "新增条目"}</h2>
            <p>{dirty ? "有未同步修改" : "本地已解锁"}</p>
          </div>
          <div className="button-row">
            <button className="ghost-button" type="button" onClick={handleCancelEdit}>
              取消
            </button>
            <button className="primary-button" type="submit">
              <Save size={17} />
              保存
            </button>
          </div>
        </div>

        <div className="form-grid">
          <label className="field">
            <span>名称</span>
            <input value={draft.title} onChange={(event) => setDraft({ ...draft, title: event.target.value })} autoFocus />
          </label>
          <label className="field">
            <span>账号</span>
            <input value={draft.username} onChange={(event) => setDraft({ ...draft, username: event.target.value })} />
          </label>
          <label className="field full">
            <span>密码</span>
            <div className="input-with-actions">
              <input
                type={showDraftPassword ? "text" : "password"}
                value={draft.password}
                onChange={(event) => setDraft({ ...draft, password: event.target.value })}
              />
              <button className="icon-button small" type="button" title="显示/隐藏" onClick={() => setShowDraftPassword(!showDraftPassword)}>
                {showDraftPassword ? <EyeOff size={15} /> : <Eye size={15} />}
              </button>
              <button
                className="icon-button small"
                type="button"
                title="生成密码"
                onClick={() => setDraft({ ...draft, password: generatePassword(passwordOptions) })}
              >
                <WandSparkles size={15} />
              </button>
            </div>
          </label>
          <div className="generator-controls full">
            <label>
              长度
              <input
                type="range"
                min={MIN_GENERATED_PASSWORD_LENGTH}
                max={MAX_GENERATED_PASSWORD_LENGTH}
                value={passwordOptions.length}
                onChange={(event) => setPasswordOptions({ ...passwordOptions, length: Number(event.target.value) })}
              />
              <span>{passwordOptions.length}</span>
            </label>
            <label>
              <input
                type="checkbox"
                checked={passwordOptions.uppercase}
                onChange={(event) => setPasswordOptions({ ...passwordOptions, uppercase: event.target.checked })}
              />
              大写
            </label>
            <label>
              <input
                type="checkbox"
                checked={passwordOptions.digits}
                onChange={(event) => setPasswordOptions({ ...passwordOptions, digits: event.target.checked })}
              />
              数字
            </label>
            <label>
              <input
                type="checkbox"
                checked={passwordOptions.symbols}
                onChange={(event) => setPasswordOptions({ ...passwordOptions, symbols: event.target.checked })}
              />
              符号
            </label>
          </div>
          <label className="field full">
            <span>网址</span>
            <input value={draft.url} onChange={(event) => setDraft({ ...draft, url: event.target.value })} />
          </label>
          <label className="field full">
            <span>标签</span>
            <input value={draft.tags} onChange={(event) => setDraft({ ...draft, tags: event.target.value })} placeholder="work, bank" />
          </label>
          <div className="form-section full">
            <div className="section-header">
              <span>自定义字段</span>
              <div className="button-row">
                <button className="ghost-button" type="button" onClick={() => handleAddCustomField("plain")}>
                  <Plus size={16} />
                  普通
                </button>
                <button className="ghost-button" type="button" onClick={() => handleAddCustomField("secret")}>
                  <Plus size={16} />
                  敏感
                </button>
              </div>
            </div>
            <div className="custom-field-editor">
              {draft.customFields.map((field) => (
                <div className="custom-field-row" key={field.id}>
                  <input
                    value={field.label}
                    onChange={(event) => handleUpdateCustomField(field.id, { label: event.target.value })}
                    placeholder="字段名"
                  />
                  <div className="input-with-actions custom-field-value">
                    <input
                      type={field.kind === "secret" && !visibleDraftFields[field.id] ? "password" : "text"}
                      value={field.value}
                      onChange={(event) => handleUpdateCustomField(field.id, { value: event.target.value })}
                      placeholder="字段值"
                    />
                    {field.kind === "secret" && (
                      <button
                        className="icon-button small"
                        type="button"
                        title={visibleDraftFields[field.id] ? "隐藏字段" : "显示字段"}
                        onClick={() => toggleDraftFieldVisibility(field.id)}
                      >
                        {visibleDraftFields[field.id] ? <EyeOff size={15} /> : <Eye size={15} />}
                      </button>
                    )}
                    <button
                      className="icon-button small"
                      type="button"
                      title="生成密码"
                      onClick={() => handleGenerateCustomField(field.id)}
                    >
                      <WandSparkles size={15} />
                    </button>
                  </div>
                  <select
                    value={field.kind}
                    onChange={(event) =>
                      handleUpdateCustomField(field.id, { kind: event.target.value as VaultCustomField["kind"] })
                    }
                  >
                    <option value="plain">普通</option>
                    <option value="secret">敏感</option>
                  </select>
                  <button className="icon-button" type="button" title="删除字段" onClick={() => handleRemoveCustomField(field.id)}>
                    <Trash2 size={16} />
                  </button>
                </div>
              ))}
              {draft.customFields.length === 0 && <span className="muted">暂无自定义字段</span>}
            </div>
          </div>
          <div className="form-section full">
            <div className="section-header">
              <span>一次性密码</span>
            </div>
            <div className="totp-editor-grid">
              <label className="field full">
                <span>密钥或 otpauth URI</span>
                <input
                  value={draft.totpSecret}
                  onChange={(event) => setDraft({ ...draft, totpSecret: event.target.value })}
                  placeholder="JBSWY3DPEHPK3PXP"
                />
              </label>
              <label className="field">
                <span>发行方</span>
                <input value={draft.totpIssuer} onChange={(event) => setDraft({ ...draft, totpIssuer: event.target.value })} />
              </label>
              <label className="field">
                <span>账号</span>
                <input value={draft.totpAccount} onChange={(event) => setDraft({ ...draft, totpAccount: event.target.value })} />
              </label>
              <label className="field">
                <span>算法</span>
                <select
                  value={draft.totpAlgorithm}
                  onChange={(event) =>
                    setDraft({ ...draft, totpAlgorithm: event.target.value as EntryDraft["totpAlgorithm"] })
                  }
                >
                  <option value="">自动</option>
                  <option value="SHA-1">SHA-1</option>
                  <option value="SHA-256">SHA-256</option>
                  <option value="SHA-512">SHA-512</option>
                </select>
              </label>
              <label className="field">
                <span>位数</span>
                <input
                  inputMode="numeric"
                  value={draft.totpDigits}
                  onChange={(event) => setDraft({ ...draft, totpDigits: event.target.value })}
                  placeholder="6"
                />
              </label>
              <label className="field">
                <span>周期</span>
                <input
                  inputMode="numeric"
                  value={draft.totpPeriod}
                  onChange={(event) => setDraft({ ...draft, totpPeriod: event.target.value })}
                  placeholder="30"
                />
              </label>
            </div>
          </div>
          <label className="field full">
            <span>备注</span>
            <textarea value={draft.notes} onChange={(event) => setDraft({ ...draft, notes: event.target.value })} rows={7} />
          </label>
        </div>
      </form>
    );
  }

  function renderEmptyDetail() {
    return (
      <div className="empty-detail">
        <KeyRound size={34} />
        <h2>没有条目</h2>
        <button className="primary-button" onClick={handleNewItem}>
          <Plus size={17} />
          新增
        </button>
      </div>
    );
  }

  function renderSettings() {
    return (
      <div className="modal-backdrop" role="dialog" aria-modal="true">
        <div className="settings-modal">
          <div className="modal-header">
            <h2>设置</h2>
            <button className="icon-button" title="关闭" onClick={() => setSettingsOpen(false)}>
              <X size={18} />
            </button>
          </div>
          <label className="field">
            <span>Dropbox App key</span>
            <input value={appKeyDraft} onChange={(event) => setAppKeyDraft(event.target.value)} autoComplete="off" />
          </label>
          <p className="muted">Redirect URI: {getDropboxRedirectUri()}</p>
          {session && (
            <form className="settings-section" onSubmit={handleChangeMasterPassword}>
              <div className="section-header">
                <span>修改主密码</span>
              </div>
              <label className="field">
                <span>新主密码</span>
                <input
                  type="password"
                  value={changedMasterPassword}
                  onChange={(event) => setChangedMasterPassword(event.target.value)}
                  autoComplete="new-password"
                  minLength={MIN_MASTER_PASSWORD_LENGTH}
                />
              </label>
              <label className="field">
                <span>确认新主密码</span>
                <input
                  type="password"
                  value={changedMasterPasswordConfirm}
                  onChange={(event) => setChangedMasterPasswordConfirm(event.target.value)}
                  autoComplete="new-password"
                  minLength={MIN_MASTER_PASSWORD_LENGTH}
                />
              </label>
              <p className="muted">修改后需要同步，其他设备才会使用新主密码。</p>
              <button className="primary-button" type="submit" disabled={Boolean(busy)}>
                <KeyRound size={17} />
                修改主密码
              </button>
            </form>
          )}
          {session && (
            <div className="settings-section">
              <div className="section-header">
                <span>本机指纹/面容解锁</span>
              </div>
              <p className="muted">
                使用 WebAuthn PRF 加密保存本机解锁密钥，仅对当前浏览器和当前站点地址有效。主密码修改后需要重新启用。
              </p>
              <div className="settings-inline-actions">
                <button
                  className="primary-button"
                  type="button"
                  onClick={() => void handleEnableBiometricUnlock()}
                  disabled={Boolean(busy) || !biometricAvailable}
                >
                  <Fingerprint size={17} />
                  {biometricUnlockInfo ? "重新启用" : "启用"}
                </button>
                {biometricUnlockInfo && (
                  <button className="ghost-button danger-text" type="button" onClick={handleDisableBiometricUnlock}>
                    <X size={16} />
                    停用
                  </button>
                )}
              </div>
              {!biometricAvailable && <p className="muted">当前浏览器或访问地址不支持 WebAuthn。请使用 HTTPS 或 localhost。</p>}
            </div>
          )}
          <div className="settings-actions">
            <button className="ghost-button" onClick={handleExportEncrypted}>
              <Download size={16} />
              导出 vault.enc
            </button>
            <button className="ghost-button" onClick={handleConnectDropbox}>
              <Cloud size={16} />
              重新连接
            </button>
            <button className="ghost-button danger-text" onClick={handleForgetDropbox}>
              <LogOut size={16} />
              移除 token
            </button>
          </div>
          <div className="modal-footer">
            <button className="ghost-button" onClick={() => setSettingsOpen(false)}>
              取消
            </button>
            <button className="primary-button" onClick={handleSaveSettings}>
              <Check size={17} />
              保存
            </button>
          </div>
        </div>
      </div>
    );
  }
}

function itemToDraft(item: VaultItem): EntryDraft {
  return {
    title: item.title,
    username: item.username,
    password: item.password,
    url: item.url,
    notes: item.notes,
    tags: item.tags.join(", "),
    customFields: item.customFields.map((field) => ({ ...field })),
    totpSecret: item.totp?.secret ?? "",
    totpIssuer: item.totp?.issuer ?? "",
    totpAccount: item.totp?.account ?? "",
    totpAlgorithm: item.totp?.algorithm ?? "",
    totpDigits: item.totp ? String(item.totp.digits) : "",
    totpPeriod: item.totp ? String(item.totp.period) : "",
  };
}

function normalizeDraftCustomFields(fields: VaultCustomField[]): VaultCustomField[] {
  return fields.flatMap((field) => {
    const label = field.label.trim();
    const value = field.value;
    if (!label && !value) {
      return [];
    }
    return [
      {
        id: field.id || randomId("field"),
        label: label || "未命名字段",
        value,
        kind: field.kind === "secret" ? "secret" : "plain",
      },
    ];
  });
}

function parseTotpDraft(draft: EntryDraft): TotpConfig | null {
  if (!draft.totpSecret.trim()) {
    return null;
  }

  const parsed = parseTotpInput(draft.totpSecret);
  const digits = parseIntegerOrFallback(draft.totpDigits, parsed.digits, 6, 8, "一次性密码位数");
  const period = parseIntegerOrFallback(draft.totpPeriod, parsed.period, 15, 120, "一次性密码周期");
  return {
    ...parsed,
    issuer: draft.totpIssuer.trim() || parsed.issuer,
    account: draft.totpAccount.trim() || parsed.account,
    algorithm: draft.totpAlgorithm || parsed.algorithm,
    digits,
    period,
  };
}

function parseIntegerOrFallback(
  value: string,
  fallback: number,
  min: number,
  max: number,
  label: string,
): number {
  if (!value.trim()) {
    return fallback;
  }
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`${label}必须是 ${min}-${max} 之间的整数。`);
  }
  return parsed;
}

function parseTags(value: string): string[] {
  return value
    .split(",")
    .map((tag) => tag.trim())
    .filter(Boolean);
}

function normalizeUrl(url: string): string {
  if (/^https?:\/\//i.test(url)) {
    return url;
  }
  return `https://${url}`;
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat("zh-CN", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

function formatTotpCode(code: string): string {
  if (code.length === 6) {
    return `${code.slice(0, 3)} ${code.slice(3)}`;
  }
  return code;
}

function getSyncStatusLabel(status: SyncStatus, dirty: boolean): string {
  if (status === "saving") return "本地保存中";
  if (status === "syncing") return "同步中";
  if (status === "remote-update") return "远端有更新";
  if (status === "offline") return "离线等待";
  if (status === "error") return "同步失败";
  if (dirty || status === "pending") return "本地有修改";
  return "已同步";
}

function getSyncButtonLabel(status: SyncStatus, dirty: boolean): string {
  if (status === "syncing") return "同步中";
  if (status === "offline") return "离线等待";
  if (dirty || status === "pending" || status === "error" || status === "remote-update") return "同步";
  return "已同步";
}

function vaultDataEqual(left: VaultData, right: VaultData): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function isOffline(): boolean {
  return navigator.onLine === false;
}

function CustomFieldDetail({
  field,
  visible,
  onToggle,
  onCopy,
}: {
  field: VaultCustomField;
  visible: boolean;
  onToggle: () => void;
  onCopy: () => void;
}) {
  return (
    <>
      <div className="detail-label">{field.label || "未命名字段"}</div>
      <div className="detail-value password-value">
        <span>{visible ? field.value || "未填写" : "••••••••••••"}</span>
        {(field.kind === "secret" || field.value) && (
          <div className="password-actions">
            {field.kind === "secret" && (
              <button className="icon-button small" title={visible ? "隐藏字段" : "显示字段"} onClick={onToggle}>
                {visible ? <EyeOff size={15} /> : <Eye size={15} />}
              </button>
            )}
            {field.value && (
              <button className="icon-button small" title="复制字段" onClick={onCopy}>
                <Copy size={15} />
              </button>
            )}
          </div>
        )}
      </div>
    </>
  );
}
