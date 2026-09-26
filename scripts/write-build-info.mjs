// Records the git SHA next to the compiled output so reports carry provenance even without .git (e.g. in Docker).
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';

let gitSha = process.env.NOIP_GIT_SHA || process.env.GITHUB_SHA || '';
if (!gitSha) {
  try {
    gitSha = execFileSync('git', ['rev-parse', 'HEAD'], { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
  } catch {
    gitSha = 'unknown';
  }
}
writeFileSync(new URL('../dist/build-info.json', import.meta.url), JSON.stringify({ gitSha }) + '\n');
console.log(`build-info: ${gitSha}`);
