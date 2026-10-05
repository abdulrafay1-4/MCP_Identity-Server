import { randomUUID } from "node:crypto";
import { createPublicKey, type JsonWebKey, type KeyObject } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { calculateJwkThumbprint, exportJWK, exportPKCS8, generateKeyPair, importPKCS8 } from "jose";
import type { JWK } from "jose";

export const SIGNING_ALG = "RS256" as const;

// active: signs new tokens, one per ring
// published: verifies tokens it signed earlier, never signs again, private key discarded
// retired: neither signs nor verifies, and is left out of /jwks.json
export type KeyState = "active" | "published" | "retired";

export interface KeyRecord {
  kid: string;
  alg: typeof SIGNING_ALG;
  state: KeyState;
  publicKey: KeyObject;
  privateKey: KeyObject | null;
  createdAt: string;
}

export interface KeyRing {
  keys: KeyRecord[];
}

export interface Jwks {
  keys: JWK[];
}

async function keyRecordFromPem(pem: string, state: KeyState): Promise<KeyRecord> {
  const privateKey = await importPKCS8<KeyObject>(pem, SIGNING_ALG);
  const publicKey = createPublicKey(privateKey);
  const publicJwk = await exportJWK(publicKey);
  const kid = await calculateJwkThumbprint(publicJwk);
  return { kid, alg: SIGNING_ALG, state, publicKey, privateKey, createdAt: new Date().toISOString() };
}

async function generateKeyRecord(state: KeyState): Promise<KeyRecord> {
  const { privateKey, publicKey } = await generateKeyPair<KeyObject>(SIGNING_ALG, { modulusLength: 2048 });
  const publicJwk = await exportJWK(publicKey);
  const kid = await calculateJwkThumbprint(publicJwk);
  return { kid, alg: SIGNING_ALG, state, publicKey, privateKey, createdAt: new Date().toISOString() };
}

/** A new ring with one active key. The kid is the key's RFC 7638 thumbprint. */
export async function loadOrGenerateKeys(signingKeyPem?: string): Promise<KeyRing> {
  const record = signingKeyPem ? await keyRecordFromPem(signingKeyPem, "active") : await generateKeyRecord("active");
  return { keys: [record] };
}

export function getActiveKey(ring: KeyRing): KeyRecord {
  const active = ring.keys.find((k) => k.state === "active");
  if (!active) {
    throw new Error("key ring has no active key");
  }
  return active;
}

export function findKey(ring: KeyRing, kid: string): KeyRecord | undefined {
  return ring.keys.find((k) => k.kid === kid);
}

export async function getJwks(ring: KeyRing): Promise<Jwks> {
  const visible = ring.keys.filter((k) => k.state === "active" || k.state === "published");
  const keys = await Promise.all(
    visible.map(async (k) => {
      const publicJwk = await exportJWK(k.publicKey);
      return { ...publicJwk, kid: k.kid, alg: k.alg, use: "sig" as const };
    })
  );
  return { keys };
}

export async function rotateKeyRing(ring: KeyRing): Promise<KeyRing> {
  const fresh = await generateKeyRecord("active");
  const demoted = ring.keys.map((k) =>
    k.state === "active" ? { ...k, state: "published" as const, privateKey: null } : k
  );
  return { keys: [...demoted, fresh] };
}

/** No-op unless the key is published. The active key has to be rotated out first. */
export function retireKey(ring: KeyRing, kid: string): KeyRing {
  return {
    keys: ring.keys.map((k) => (k.kid === kid && k.state === "published" ? { ...k, state: "retired" as const } : k))
  };
}

interface PersistedKeyRecord {
  kid: string;
  alg: typeof SIGNING_ALG;
  state: KeyState;
  publicJwk: JWK;
  privateKeyPem: string | null;
  createdAt: string;
}

interface PersistedKeyRing {
  version: 1;
  keys: PersistedKeyRecord[];
}

async function serializeKeyRing(ring: KeyRing): Promise<PersistedKeyRing> {
  const keys = await Promise.all(
    ring.keys.map(
      async (k): Promise<PersistedKeyRecord> => ({
        kid: k.kid,
        alg: k.alg,
        state: k.state,
        publicJwk: await exportJWK(k.publicKey),
        privateKeyPem: k.privateKey ? await exportPKCS8(k.privateKey) : null,
        createdAt: k.createdAt
      })
    )
  );
  return { version: 1, keys };
}

async function deserializeKeyRing(persisted: PersistedKeyRing): Promise<KeyRing> {
  const keys = await Promise.all(
    persisted.keys.map(async (k): Promise<KeyRecord> => {
      const publicKey = createPublicKey({ key: k.publicJwk as JsonWebKey, format: "jwk" });
      const privateKey = k.privateKeyPem ? await importPKCS8<KeyObject>(k.privateKeyPem, k.alg) : null;
      return { kid: k.kid, alg: k.alg, state: k.state, publicKey, privateKey, createdAt: k.createdAt };
    })
  );
  return { keys };
}

/**
 * A missing file is normal on first boot. A corrupt one must fail loudly: generating a
 * fresh ring would orphan every token already issued.
 */
async function readKeyRingFile(path: string): Promise<KeyRing | undefined> {
  let raw: string;
  try {
    raw = await readFile(path, "utf-8");
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return undefined;
    }
    throw error;
  }
  return deserializeKeyRing(JSON.parse(raw) as PersistedKeyRing);
}

/**
 * Written to a temp file and renamed into place, so a crash can't leave a torn file.
 * Mode 0600 because it holds the active private key.
 */
export async function saveKeyRing(path: string, ring: KeyRing): Promise<void> {
  const persisted = await serializeKeyRing(ring);
  await mkdir(dirname(path), { recursive: true });
  const tmpPath = `${path}.${randomUUID()}.tmp`;
  await writeFile(tmpPath, JSON.stringify(persisted, null, 2), { mode: 0o600 });
  await rename(tmpPath, path);
}

export async function loadPersistedKeyRing(path: string, signingKeyPem?: string): Promise<KeyRing> {
  const existing = await readKeyRingFile(path);
  if (existing) {
    return existing;
  }
  const ring = await loadOrGenerateKeys(signingKeyPem);
  await saveKeyRing(path, ring);
  return ring;
}
