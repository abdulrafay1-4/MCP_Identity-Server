import { MemoryTokenStore } from "../src/store/memory.js";
import { runTokenStoreContractTests, type TokenStoreHarness } from "./support/tokenStoreContract.js";

async function buildHarness(): Promise<TokenStoreHarness> {
  let current = new Date();
  const store = new MemoryTokenStore({ now: () => current });
  return { store, setNow: (date) => (current = date) };
}

runTokenStoreContractTests("MemoryTokenStore", buildHarness);
