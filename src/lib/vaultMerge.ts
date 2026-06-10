import type { PasswordHistoryItem, TotpConfig, VaultCustomField, VaultData, VaultItem } from "../types";

export type VaultMergeResult = {
  data: VaultData;
  conflicts: number;
};

const SCALAR_KEYS = ["title", "username", "password", "url", "notes"] as const;
const STRUCTURED_KEYS = ["tags", "customFields", "totp"] as const;

export function mergeVaults(base: VaultData | null, local: VaultData, remote: VaultData): VaultMergeResult {
  const baseItems = toItemMap(base?.items ?? []);
  const localItems = toItemMap(local.items);
  const remoteItems = toItemMap(remote.items);
  const itemIds = new Set([...baseItems.keys(), ...localItems.keys(), ...remoteItems.keys()]);
  let conflicts = 0;
  const items: VaultItem[] = [];

  itemIds.forEach((id) => {
    const merged = mergeItem(baseItems.get(id), localItems.get(id), remoteItems.get(id));
    conflicts += merged.conflicts;
    if (merged.item) {
      items.push(merged.item);
    }
  });

  items.sort((left, right) => compareIso(getItemStamp(right), getItemStamp(left)));

  return {
    data: {
      version: 1,
      meta: {
        createdAt: minIso([base?.meta.createdAt, local.meta.createdAt, remote.meta.createdAt]),
        updatedAt: maxIso([
          base?.meta.updatedAt,
          local.meta.updatedAt,
          remote.meta.updatedAt,
          ...items.map(getItemStamp),
        ]),
      },
      items,
    },
    conflicts,
  };
}

function mergeItem(
  baseItem: VaultItem | undefined,
  localItem: VaultItem | undefined,
  remoteItem: VaultItem | undefined,
): { item: VaultItem | null; conflicts: number } {
  if (!localItem && !remoteItem) {
    return { item: null, conflicts: 0 };
  }
  if (!localItem) {
    if (!remoteItem) {
      return { item: null, conflicts: 0 };
    }
    return { item: cloneItem(remoteItem), conflicts: 0 };
  }
  if (!remoteItem) {
    return { item: cloneItem(localItem), conflicts: 0 };
  }
  if (itemsEqual(localItem, remoteItem)) {
    return { item: cloneItem(localItem), conflicts: 0 };
  }

  if (!baseItem) {
    const newer = chooseNewer(localItem, remoteItem);
    return {
      item: withMergedPasswordHistory(cloneItem(newer), localItem, remoteItem),
      conflicts: 1,
    };
  }

  const localChanged = !itemsEqual(baseItem, localItem);
  const remoteChanged = !itemsEqual(baseItem, remoteItem);
  if (localChanged && !remoteChanged) {
    return { item: cloneItem(localItem), conflicts: 0 };
  }
  if (!localChanged && remoteChanged) {
    return { item: cloneItem(remoteItem), conflicts: 0 };
  }
  if (!localChanged && !remoteChanged) {
    return { item: cloneItem(localItem), conflicts: 0 };
  }

  const tombstoneWinner = chooseTombstoneWinner(localItem, remoteItem);
  if (tombstoneWinner) {
    return {
      item: cloneItem(tombstoneWinner),
      conflicts: localItem.deletedAt && remoteItem.deletedAt ? 0 : 1,
    };
  }

  if (localItem.deletedAt || remoteItem.deletedAt) {
    return {
      item: cloneItem(chooseNewer(localItem, remoteItem)),
      conflicts: 1,
    };
  }

  return mergeActiveItem(baseItem, localItem, remoteItem);
}

function mergeActiveItem(
  baseItem: VaultItem,
  localItem: VaultItem,
  remoteItem: VaultItem,
): { item: VaultItem; conflicts: number } {
  let conflicts = 0;
  const merged = cloneItem(localItem);

  SCALAR_KEYS.forEach((key) => {
    const localChanged = localItem[key] !== baseItem[key];
    const remoteChanged = remoteItem[key] !== baseItem[key];
    if (!localChanged && remoteChanged) {
      merged[key] = remoteItem[key];
      return;
    }
    if (localChanged && remoteChanged && localItem[key] !== remoteItem[key]) {
      conflicts += 1;
    }
  });

  STRUCTURED_KEYS.forEach((key) => {
    const localChanged = !jsonEqual(localItem[key], baseItem[key]);
    const remoteChanged = !jsonEqual(remoteItem[key], baseItem[key]);
    if (!localChanged && remoteChanged) {
      assignStructuredValue(merged, key, remoteItem[key]);
      return;
    }
    if (localChanged && remoteChanged && !jsonEqual(localItem[key], remoteItem[key])) {
      conflicts += 1;
    }
  });

  merged.createdAt = minIso([baseItem.createdAt, localItem.createdAt, remoteItem.createdAt]);
  merged.updatedAt = maxIso([baseItem.updatedAt, localItem.updatedAt, remoteItem.updatedAt]);
  delete merged.deletedAt;
  merged.passwordHistory = mergePasswordHistory(merged, localItem, remoteItem);
  return { item: merged, conflicts };
}

function assignStructuredValue(
  item: VaultItem,
  key: (typeof STRUCTURED_KEYS)[number],
  value: string[] | VaultCustomField[] | TotpConfig | null,
): void {
  if (key === "tags") {
    item.tags = [...(value as string[])];
    return;
  }
  if (key === "customFields") {
    item.customFields = (value as VaultCustomField[]).map((field) => ({ ...field }));
    return;
  }
  item.totp = value ? ({ ...(value as TotpConfig) } as TotpConfig) : null;
}

function chooseTombstoneWinner(localItem: VaultItem, remoteItem: VaultItem): VaultItem | null {
  if (localItem.deletedAt && compareIso(localItem.deletedAt, getItemStamp(remoteItem)) >= 0) {
    return localItem;
  }
  if (remoteItem.deletedAt && compareIso(remoteItem.deletedAt, getItemStamp(localItem)) > 0) {
    return remoteItem;
  }
  return null;
}

function chooseNewer(left: VaultItem, right: VaultItem): VaultItem {
  return compareIso(getItemStamp(left), getItemStamp(right)) >= 0 ? left : right;
}

function withMergedPasswordHistory(target: VaultItem, localItem: VaultItem, remoteItem: VaultItem): VaultItem {
  target.passwordHistory = mergePasswordHistory(target, localItem, remoteItem);
  return target;
}

function mergePasswordHistory(target: VaultItem, localItem: VaultItem, remoteItem: VaultItem): PasswordHistoryItem[] {
  const history = [...target.passwordHistory, ...localItem.passwordHistory, ...remoteItem.passwordHistory];
  addPasswordSnapshot(history, target, localItem, "local");
  addPasswordSnapshot(history, target, remoteItem, "remote");

  const seen = new Set<string>();
  return history
    .filter((historyItem) => {
      const key = `${historyItem.password}\u0000${historyItem.changedAt}`;
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    })
    .sort((left, right) => compareIso(right.changedAt, left.changedAt))
    .slice(0, 50);
}

function addPasswordSnapshot(
  history: PasswordHistoryItem[],
  target: VaultItem,
  candidate: VaultItem,
  source: "local" | "remote",
): void {
  if (!candidate.password || candidate.password === target.password) {
    return;
  }
  history.push({
    id: `merge-${source}-${candidate.id}-${compactTimestamp(getItemStamp(candidate))}`,
    password: candidate.password,
    changedAt: getItemStamp(candidate),
  });
}

function toItemMap(items: VaultItem[]): Map<string, VaultItem> {
  return new Map(items.map((item) => [item.id, item]));
}

function cloneItem(item: VaultItem): VaultItem {
  const clone: VaultItem = {
    ...item,
    tags: [...item.tags],
    customFields: item.customFields.map((field) => ({ ...field })),
    passwordHistory: item.passwordHistory.map((historyItem) => ({ ...historyItem })),
    totp: item.totp ? { ...item.totp } : null,
  };
  if (!item.deletedAt) {
    delete clone.deletedAt;
  }
  return clone;
}

function itemsEqual(left: VaultItem, right: VaultItem): boolean {
  return jsonEqual(left, right);
}

function jsonEqual(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function getItemStamp(item: VaultItem): string {
  return item.deletedAt ?? item.updatedAt ?? item.createdAt;
}

function compareIso(left: string, right: string): number {
  return Date.parse(left) - Date.parse(right);
}

function minIso(values: Array<string | undefined>): string {
  const existing = values.filter((value): value is string => Boolean(value));
  if (!existing.length) {
    return new Date().toISOString();
  }
  return existing.reduce((min, value) => (compareIso(value, min) < 0 ? value : min), existing[0]);
}

function maxIso(values: Array<string | undefined>): string {
  const existing = values.filter((value): value is string => Boolean(value));
  if (!existing.length) {
    return new Date().toISOString();
  }
  return existing.reduce((max, value) => (compareIso(value, max) > 0 ? value : max), existing[0]);
}

function compactTimestamp(value: string): string {
  return value.replace(/[^0-9A-Za-z]/g, "");
}
