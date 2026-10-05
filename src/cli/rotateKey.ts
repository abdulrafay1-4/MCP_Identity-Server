import { loadConfig } from "../config/env.js";
import { getActiveKey, loadPersistedKeyRing, retireKey, rotateKeyRing, saveKeyRing } from "../keys.js";
import { createLogger } from "../log.js";
import { createStore } from "../store/factory.js";

const log = createLogger({ level: "info" });

// Best effort: the ring file is already written, so an unreachable audit store must
// not make the rotation look like it failed.
async function recordKeyAudit(
  config: ReturnType<typeof loadConfig>,
  eventType: string,
  subject: string,
  metadata: Record<string, unknown>
): Promise<void> {
  try {
    const { store, close } = await createStore({ databaseUrl: config.databaseUrl });
    try {
      await store.recordAuditEvent(eventType, subject, metadata);
    } finally {
      await close();
    }
  } catch (error: unknown) {
    log.warn("key_audit_write_failed", {
      eventType,
      reason: error instanceof Error ? error.message : "unknown error"
    });
  }
}

// npm run rotate-key                   new active key; the old one keeps verifying but stops signing
// npm run rotate-key -- retire <kid>   stop accepting a published key at all
// The server reads the ring at startup, so restart it after a rotation.
async function main(): Promise<void> {
  const config = loadConfig();
  const [command, arg] = process.argv.slice(2);

  const ring = await loadPersistedKeyRing(config.keyRingPath, config.signingKey);

  if (command === undefined || command === "rotate") {
    const previousActive = ring.keys.find((k) => k.state === "active");
    const rotated = await rotateKeyRing(ring);
    await saveKeyRing(config.keyRingPath, rotated);
    const newActive = getActiveKey(rotated);
    console.log("mcp-identity: rotated signing key");
    console.log(`  ring: ${config.keyRingPath}`);
    if (previousActive) {
      console.log(`  ${previousActive.kid}: active -> published`);
    }
    console.log(`  ${newActive.kid}: (new) -> active`);
    await recordKeyAudit(config, "key_rotated", newActive.kid, { previous_kid: previousActive?.kid ?? null });
    return;
  }

  if (command === "retire") {
    if (!arg) {
      console.error("mcp-identity: retire requires a kid, e.g. `npm run rotate-key -- retire <kid>`");
      process.exitCode = 1;
      return;
    }
    const before = ring.keys.find((k) => k.kid === arg);
    if (!before || before.state !== "published") {
      console.error(
        `mcp-identity: kid ${arg} is not currently a published key (found: ${before ? before.state : "no such kid"}). Only a published key can be retired.`
      );
      process.exitCode = 1;
      return;
    }
    const retired = retireKey(ring, arg);
    await saveKeyRing(config.keyRingPath, retired);
    console.log("mcp-identity: retired key");
    console.log(`  ring: ${config.keyRingPath}`);
    console.log(`  ${arg}: published -> retired`);
    await recordKeyAudit(config, "key_retired", arg, {});
    return;
  }

  console.error(`mcp-identity: unknown command "${command}". Usage: rotate-key [rotate|retire <kid>]`);
  process.exitCode = 1;
}

main().catch((error: unknown) => {
  console.error("mcp-identity: key rotation failed:", error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
