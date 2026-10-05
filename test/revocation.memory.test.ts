import { MemoryTokenStore } from "../src/store/memory.js";
import { runRevocationTests } from "./support/revocationContract.js";

runRevocationTests("MemoryTokenStore", (now) => new MemoryTokenStore({ now }));
