# Easy Pass Sync Strategy

Easy Pass uses GitHub Pages for the frontend and Dropbox App Folder storage for a single encrypted `vault.enc` file. There is no application server. The browser owns all encryption, merge, and retry behavior.

## Goals

- Keep the default workflow automatic after the vault is unlocked.
- Never upload plaintext vault data.
- Avoid silent remote overwrites by using Dropbox revision checks.
- Survive tab close, refresh, offline periods, and short network failures.
- Merge normal multi-device edits without asking the user to manually choose a file.

## Storage Model

- Remote source of truth: Dropbox `/vault.enc`.
- Local pending copy: encrypted `vault.enc` text in browser storage.
- In-memory base: last decrypted vault data that is known to match the latest Dropbox revision.
- In-memory working copy: current unlocked vault data.

The local pending copy is still encrypted with Argon2id + AES-256-GCM. It exists only to recover unsynced local edits after refresh or lock.

## Local Edit Flow

1. Any vault mutation updates the unlocked working copy and marks it dirty.
2. After 300 ms of no further local mutation, the working copy is sealed into encrypted `vault.enc` text and saved locally as pending data.
3. After 3 seconds of no further local mutation, the app attempts an automatic Dropbox upload.
4. If the browser is offline or Dropbox is disconnected, the pending encrypted copy remains local and the status becomes waiting/offline.

Manual sync remains available and uses the same upload path as automatic sync.

## Dropbox Upload Flow

1. Seal the current working copy to encrypted `vault.enc`.
2. Upload with Dropbox `mode: update` when a known remote rev exists.
3. Upload with Dropbox `mode: add` only when the remote file is missing.
4. On successful upload:
   - update the known Dropbox rev,
   - update the in-memory base to the uploaded decrypted data,
   - clear the dirty flag,
   - clear the encrypted local pending copy.

Dropbox revision checks are the guard against silent overwrite.

## Remote Check Flow

The app checks remote metadata only:

- after unlock,
- when the tab regains focus,
- when the browser comes online,
- every 60 seconds while unlocked and connected.

If the Dropbox rev has not changed, no download is performed. If the rev changed, the app downloads and decrypts `/vault.enc` with the current key context.

## Conflict Handling

A conflict is detected when upload with `mode: update` fails because the Dropbox rev changed.

Conflict resolution flow:

1. Download the latest remote encrypted vault.
2. Decrypt it using the current in-memory key context.
3. Merge `base`, `local`, and `remote` vault data by item id.
4. Preserve delete tombstones.
5. Prefer non-conflicting field changes automatically.
6. For same-field conflicts, keep local edits and preserve alternate passwords in password history when possible.
7. Upload the merged vault using the latest remote rev.

If the remote vault uses a different key derivation context, automatic merge is blocked and the user must lock and unlock with the correct master password.

## Delete Tombstones

Deletes are represented as item tombstones:

```json
{
  "id": "entry_x",
  "deletedAt": "2026-06-10T12:00:00.000Z",
  "updatedAt": "2026-06-10T12:00:00.000Z"
}
```

The UI hides tombstoned items, but sync and merge keep them so a delete made on one device can propagate to another device.

## Status States

- `synced`: current working copy matches Dropbox.
- `pending`: local encrypted pending data exists.
- `saving`: local encrypted pending copy is being written.
- `syncing`: Dropbox upload/download/merge is running.
- `remote-update`: Dropbox rev changed and will be pulled or merged.
- `offline`: browser is offline and local changes are waiting.
- `error`: last automatic sync attempt failed.

## Known Limits

- Local pending data uses browser storage, so very large vault files may hit browser quota.
- Same-field conflicts are resolved automatically with local priority.
- Master password rotation conflicts cannot be merged unless the current key context can decrypt the remote file.
