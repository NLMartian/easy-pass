import {
  Check,
  Cloud,
  CloudOff,
  Copy,
  Download,
  Eye,
  EyeOff,
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
  hasOAuthRedirect,
  isDropboxConflict,
  RemoteVault,
  startDropboxAuth,
  uploadRemoteVault,
} from "./lib/dropboxSync";
import { randomId } from "./lib/encoding";
import {
  DEFAULT_PASSWORD_OPTIONS,
  generatePassword,
  MAX_GENERATED_PASSWORD_LENGTH,
  MIN_GENERATED_PASSWORD_LENGTH,
  PasswordGeneratorOptions,
} from "./lib/passwords";
import {
  DropboxTokenInfo,
  hasDropboxToken,
  loadDropboxAppKey,
  loadDropboxTokenInfo,
  saveDropboxAppKey,
  saveDropboxTokenInfo,
} from "./lib/storage";
import {
  createVaultSession,
  sealVault,
  unlockVault,
  unlockVaultWithKeyContext,
  VAULT_FILE_NAME,
} from "./lib/vault";
import { generateTotp, parseTotpInput, type TotpCode } from "./lib/totp";
import type { TotpConfig, VaultCustomField, VaultItem, VaultSession } from "./types";

type Notice = {
  kind: "info" | "success" | "error";
  text: string;
} | null;

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

export function App() {
  const [appKey, setAppKey] = useState(loadDropboxAppKey);
  const [appKeyDraft, setAppKeyDraft] = useState(appKey);
  const [tokens, setTokens] = useState<DropboxTokenInfo | null>(loadDropboxTokenInfo);
  const [remoteVault, setRemoteVault] = useState<RemoteVault | null>(null);
  const [remoteMissing, setRemoteMissing] = useState(false);
  const [session, setSession] = useState<VaultSession | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<Notice>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [unlockPassword, setUnlockPassword] = useState("");
  const [newMasterPassword, setNewMasterPassword] = useState("");
  const [newMasterPasswordConfirm, setNewMasterPasswordConfirm] = useState("");
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

  const connected = hasDropboxToken(tokens);
  const items = session?.data.items ?? [];
  const selectedItem = useMemo(
    () => items.find((item) => item.id === selectedId) ?? null,
    [items, selectedId],
  );
  const filteredItems = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    if (!normalizedQuery) return items;
    return items.filter((item) => {
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
  }, [items, query]);

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
    if (!selectedId && session.data.items[0]) {
      setSelectedId(session.data.items[0].id);
      return;
    }
    if (selectedId && !session.data.items.some((item) => item.id === selectedId)) {
      setSelectedId(session.data.items[0]?.id ?? null);
    }
  }, [selectedId, session]);

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
      setDirty(false);
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
    setDirty(false);
    autoLoadAttempted.current = false;
    setNotice({ kind: "info", text: "已移除本机 Dropbox token。" });
  }

  function handleLockVault() {
    if (dirty && !window.confirm("有未同步修改。仍要锁定密码库吗？")) {
      return;
    }
    setSession(null);
    setSelectedId(null);
    setEditingId(null);
    setUnlockPassword("");
    setDirty(false);
    setNotice({ kind: "info", text: "密码库已锁定。" });
  }

  async function handleUnlock(event: FormEvent) {
    event.preventDefault();
    if (!remoteVault) {
      setNotice({ kind: "error", text: "请先从 Dropbox 读取 vault.enc。" });
      return;
    }
    setBusy("解锁密码库");
    try {
      const nextSession = await unlockVault(remoteVault.text, unlockPassword);
      setSession(nextSession);
      setUnlockPassword("");
      setDirty(false);
      setSelectedId(nextSession.data.items[0]?.id ?? null);
      setNotice({ kind: "success", text: "密码库已解锁。" });
    } catch (error) {
      setNotice({ kind: "error", text: error instanceof Error ? error.message : "解锁失败。" });
    } finally {
      setBusy(null);
    }
  }

  async function handleCreateVault(event: FormEvent) {
    event.preventDefault();
    if (!connected) {
      setNotice({ kind: "error", text: "请先连接 Dropbox。" });
      return;
    }
    if (newMasterPassword.length < 12) {
      setNotice({ kind: "error", text: "主密码至少 12 个字符。" });
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
      setSession({ ...nextSession, data: sealed.data });
      setDirty(false);
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
    if (!session) return;
    setBusy("加密并同步");
    try {
      const context = await requireDropboxClient();
      const sealed = await sealVault(session);
      const uploaded = await uploadRemoteVault(context.dbx, sealed.text, remoteVault?.rev ?? null);
      setRemoteVault(uploaded);
      setSession({ ...session, data: sealed.data });
      setDirty(false);
      setNotice({ kind: "success", text: "已同步到 Dropbox。" });
    } catch (error) {
      setNotice({
        kind: "error",
        text: isDropboxConflict(error)
          ? "远端 vault.enc 已变化。请先拉取远端或确认后再处理。"
          : formatDropboxError(error),
      });
    } finally {
      setBusy(null);
    }
  }

  async function handlePullRemoteIntoSession() {
    if (!session) return;
    if (dirty) {
      setNotice({ kind: "error", text: "当前有未同步修改，先同步或锁定后再拉取。" });
      return;
    }
    const downloaded = await refreshRemoteVault();
    if (!downloaded) return;

    setBusy("解密远端密码库");
    try {
      const nextSession = await unlockVaultWithKeyContext(downloaded.text, session.keyContext);
      setSession(nextSession);
      setSelectedId(nextSession.data.items[0]?.id ?? null);
      setNotice({ kind: "success", text: "已加载远端最新数据。" });
    } catch (error) {
      setNotice({ kind: "error", text: error instanceof Error ? error.message : "无法加载远端数据。" });
    } finally {
      setBusy(null);
    }
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
    setDirty(true);
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
          items: previous.data.items.filter((candidate) => candidate.id !== item.id),
        },
      };
    });
    setDirty(true);
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
    if (!appKey || !tokens || !hasDropboxToken(tokens)) {
      throw new Error("请先连接 Dropbox。");
    }
    const context = await createDropboxClient(appKey, tokens);
    saveDropboxTokenInfo(context.tokens);
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
            <p>{session ? `${items.length} 个条目` : "端到端加密密码库"}</p>
          </div>
        </div>

        <div className="topbar-actions">
          <span className={`sync-pill ${connected ? "connected" : ""}`}>
            {connected ? <Cloud size={16} /> : <CloudOff size={16} />}
            {connected ? "Dropbox" : "未连接"}
          </span>
          {session && (
            <>
              <button className="icon-button" title="拉取远端" onClick={handlePullRemoteIntoSession} disabled={Boolean(busy)}>
                <Download size={18} />
              </button>
              <button
                className="primary-button"
                onClick={handleSyncVault}
                disabled={Boolean(busy) || !dirty}
                title="同步到 Dropbox"
              >
                <Save size={17} />
                {dirty ? "同步" : "已同步"}
              </button>
              <button className="icon-button" title="锁定" onClick={handleLockVault}>
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
              />
            </label>
            <label className="field">
              <span>确认主密码</span>
              <input
                type="password"
                value={newMasterPasswordConfirm}
                onChange={(event) => setNewMasterPasswordConfirm(event.target.value)}
                autoComplete="new-password"
              />
            </label>
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
            <button className="icon-button small" title={showPassword ? "隐藏密码" : "显示密码"} onClick={() => setShowPassword(!showPassword)}>
              {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
            </button>
            <button className="icon-button small" title="复制密码" onClick={() => void copyToClipboard(item.password, "密码")}>
              <Copy size={15} />
            </button>
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
    </>
  );
}
