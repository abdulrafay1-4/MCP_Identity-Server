import { MemoryTokenStore } from "../src/store/memory.js";
import { runDelegationTests } from "./support/delegationContract.js";

runDelegationTests("MemoryTokenStore", (now) => new MemoryTokenStore({ now }));
