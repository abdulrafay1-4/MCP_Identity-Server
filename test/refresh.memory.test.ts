import { MemoryTokenStore } from "../src/store/memory.js";
import { runRefreshTests } from "./support/refreshContract.js";

runRefreshTests("MemoryTokenStore", (now) => new MemoryTokenStore({ now }));
