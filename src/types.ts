export type VaultItem = {
  id: string;
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  tags: string[];
  createdAt: string;
  updatedAt: string;
};

export type VaultData = {
  version: 1;
  meta: {
    createdAt: string;
    updatedAt: string;
  };
  items: VaultItem[];
};

export type KdfParams = {
  name: "Argon2id";
  memoryKiB: number;
  iterations: number;
  parallelism: number;
  hashLength: number;
  salt: string;
};

export type VaultEnvelope = {
  app: "easy-pass";
  version: 1;
  cipher: "AES-256-GCM";
  kdf: KdfParams;
  nonce: string;
  createdAt: string;
  updatedAt: string;
  ciphertext: string;
};

export type VaultKeyContext = {
  key: CryptoKey;
  kdf: KdfParams;
  createdAt: string;
};

export type VaultSession = {
  data: VaultData;
  keyContext: VaultKeyContext;
};
