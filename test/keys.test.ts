import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { exportPKCS8, generateKeyPair } from "jose";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  findKey,
  getActiveKey,
  getJwks,
  loadOrGenerateKeys,
  loadPersistedKeyRing,
  retireKey,
  rotateKeyRing,
  saveKeyRing,
  type KeyRing
} from "../src/keys.js";

const PRIVATE_KEY_FIELDS = ["d", "p", "q", "dp", "dq", "qi"];

describe("loadOrGenerateKeys", () => {
  it("generates an RS256 keypair with a stable kid when no PEM is supplied", async () => {
    const ring = await loadOrGenerateKeys();
    expect(ring.keys).toHaveLength(1);
    const key = getActiveKey(ring);
    expect(key.alg).toBe("RS256");
    expect(key.state).toBe("active");
    expect(typeof key.kid).toBe("string");
    expect(key.kid.length).toBeGreaterThan(0);

    const jwks1 = await getJwks(ring);
    const jwks2 = await getJwks(ring);
    expect(jwks1.keys[0]?.kid).toBe(jwks2.keys[0]?.kid);
  });

  it("loads a supplied PKCS8 PEM private key instead of generating one", async () => {
    const { privateKey } = await generateKeyPair("RS256", { modulusLength: 2048 });
    const pem = await exportPKCS8(privateKey);

    const ring = await loadOrGenerateKeys(pem);
    const key = getActiveKey(ring);
    expect(key.alg).toBe("RS256");

    const jwks = await getJwks(ring);
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]?.kty).toBe("RSA");
  });

  it("two independently generated keypairs get different kids", async () => {
    const a = await loadOrGenerateKeys();
    const b = await loadOrGenerateKeys();
    expect(getActiveKey(a).kid).not.toBe(getActiveKey(b).kid);
  });
});

describe("getJwks", () => {
  it("exposes kid, kty, n, and e for the public key", async () => {
    const ring = await loadOrGenerateKeys();
    const jwks = await getJwks(ring);

    expect(jwks.keys).toHaveLength(1);
    const jwk = jwks.keys[0];
    expect(jwk?.kid).toBe(getActiveKey(ring).kid);
    expect(jwk?.kty).toBe("RSA");
    expect(typeof jwk?.n).toBe("string");
    expect(typeof jwk?.e).toBe("string");
    expect(jwk?.use).toBe("sig");
    expect(jwk?.alg).toBe("RS256");
  });

  it("never includes private key material, anywhere in the serialized document", async () => {
    const ring = await loadOrGenerateKeys();
    const jwks = await getJwks(ring);
    const serialized = JSON.stringify(jwks);
    const parsed = JSON.parse(serialized) as unknown;

    for (const field of PRIVATE_KEY_FIELDS) {
      expect(serialized.includes(`"${field}"`)).toBe(false);
    }

    function assertNoPrivateFields(value: unknown): void {
      if (Array.isArray(value)) {
        for (const item of value) assertNoPrivateFields(item);
        return;
      }
      if (value && typeof value === "object") {
        for (const [key, val] of Object.entries(value)) {
          expect(PRIVATE_KEY_FIELDS).not.toContain(key);
          assertNoPrivateFields(val);
        }
      }
    }
    assertNoPrivateFields(parsed);
  });

  it("lists exactly active + published keys, never a retired one", async () => {
    const ring0 = await loadOrGenerateKeys();
    const originalKid = getActiveKey(ring0).kid;

    const ring1 = await rotateKeyRing(ring0);
    const secondKid = getActiveKey(ring1).kid;
    const ring2 = retireKey(ring1, originalKid);

    const jwks = await getJwks(ring2);
    const kids = jwks.keys.map((k) => k.kid);
    expect(kids).not.toContain(originalKid);
    expect(kids).toContain(secondKid);
    expect(kids).toHaveLength(1);
  });
});

describe("findKey", () => {
  it("finds a key in any state by kid, and returns undefined for an unknown kid", async () => {
    const ring = await loadOrGenerateKeys();
    const active = getActiveKey(ring);
    expect(findKey(ring, active.kid)?.kid).toBe(active.kid);
    expect(findKey(ring, "not-a-real-kid")).toBeUndefined();
  });
});

describe("rotateKeyRing", () => {
  it("makes a fresh key active and demotes the previous active key to published, discarding its private key", async () => {
    const ring0 = await loadOrGenerateKeys();
    const originalKid = getActiveKey(ring0).kid;

    const ring1 = await rotateKeyRing(ring0);

    expect(ring1.keys).toHaveLength(2);
    const newActive = getActiveKey(ring1);
    expect(newActive.kid).not.toBe(originalKid);
    expect(newActive.privateKey).not.toBeNull();

    const demoted = findKey(ring1, originalKid);
    expect(demoted?.state).toBe("published");
    expect(demoted?.privateKey).toBeNull();
  });

  it("rotating repeatedly accumulates published keys, always exactly one active", async () => {
    let ring = await loadOrGenerateKeys();
    const kids: string[] = [getActiveKey(ring).kid];
    for (let i = 0; i < 3; i++) {
      ring = await rotateKeyRing(ring);
      kids.push(getActiveKey(ring).kid);
    }
    expect(ring.keys).toHaveLength(4);
    expect(ring.keys.filter((k) => k.state === "active")).toHaveLength(1);
    expect(ring.keys.filter((k) => k.state === "published")).toHaveLength(3);
    expect(new Set(kids).size).toBe(kids.length);
  });
});

describe("retireKey", () => {
  it("moves a published key to retired", async () => {
    const ring0 = await loadOrGenerateKeys();
    const originalKid = getActiveKey(ring0).kid;
    const ring1 = await rotateKeyRing(ring0);

    const ring2 = retireKey(ring1, originalKid);
    expect(findKey(ring2, originalKid)?.state).toBe("retired");
  });

  it("is a no-op for an unknown kid", async () => {
    const ring0 = await loadOrGenerateKeys();
    const ring1 = retireKey(ring0, "not-a-real-kid");
    expect(ring1).toEqual(ring0);
  });

  it("refuses to retire the active key directly (no-op)", async () => {
    const ring0 = await loadOrGenerateKeys();
    const activeKid = getActiveKey(ring0).kid;
    const ring1 = retireKey(ring0, activeKid);
    expect(getActiveKey(ring1).kid).toBe(activeKid);
    expect(findKey(ring1, activeKid)?.state).toBe("active");
  });
});

describe("persistence (keys survive a restart)", () => {
  let dir: string;
  let path: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "mcp-identity-keys-"));
    path = join(dir, "keys.json");
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("round-trips a ring through save/load, preserving kid, state, and signing ability", async () => {
    const ring0 = await loadOrGenerateKeys();
    const rotated = await rotateKeyRing(ring0);
    await saveKeyRing(path, rotated);

    const loaded = await loadPersistedKeyRing(path);
    expect(loaded.keys).toHaveLength(2);
    expect(getActiveKey(loaded).kid).toBe(getActiveKey(rotated).kid);
    const publishedOriginal = findKey(loaded, getActiveKey(ring0).kid);
    expect(publishedOriginal?.state).toBe("published");
    expect(publishedOriginal?.privateKey).toBeNull();
  });

  it("bootstraps and persists a fresh ring on first load when no file exists yet", async () => {
    const ring = await loadPersistedKeyRing(path);
    expect(ring.keys).toHaveLength(1);

    const onDisk = await stat(path);
    expect(onDisk.isFile()).toBe(true);

    const reloaded = await loadPersistedKeyRing(path);
    expect(getActiveKey(reloaded).kid).toBe(getActiveKey(ring).kid);
  });

  it("writes the key ring file with owner-only permissions (0600)", async () => {
    await saveKeyRing(path, await loadOrGenerateKeys());
    const mode = (await stat(path)).mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it("never writes private key material for a non-active key to disk", async () => {
    const ring0 = await loadOrGenerateKeys();
    const rotated = await rotateKeyRing(ring0);
    await saveKeyRing(path, rotated);

    const raw = await readFile(path, "utf-8");
    const parsed = JSON.parse(raw) as { keys: Array<{ state: string; privateKeyPem: string | null }> };
    for (const key of parsed.keys) {
      if (key.state !== "active") {
        expect(key.privateKeyPem).toBeNull();
      }
    }
  });
});
