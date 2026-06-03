import test from "node:test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

const execFileAsync = promisify(execFile);

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const tscExecutable = process.platform === "win32" ? "npx.cmd" : "npx";

async function runTsc(projectPath) {
  const args = ["tsc", "--project", projectPath];
  // shell: true is required on Windows to spawn the npx.cmd batch shim without EINVAL.
  await execFileAsync(tscExecutable, args, { cwd: __dirname, shell: process.platform === "win32" });
}

test("TypeScript export map smoke test", async () => {
  await runTsc("tsconfig.types-smoke.json");
});
