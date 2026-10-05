import { afterAll, beforeAll, describe } from "vitest";
import { PgTokenStore } from "../src/store/postgres/pgStore.js";
import { runDelegationTests } from "./support/delegationContract.js";
import { createMigratedPglite, type PgliteHandle } from "./support/pglite.js";

describe("delegation over pglite", () => {
  let handle: PgliteHandle;

  beforeAll(async () => {
    handle = await createMigratedPglite();
  });

  afterAll(async () => {
    await handle?.close();
  });

  runDelegationTests("PgTokenStore (pglite)", (now) => new PgTokenStore(handle.db, { now }));
});
