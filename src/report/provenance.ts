import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

// src/report/x.ts and dist/report/x.js are both two levels below the package root.
const ROOT = new URL('../../', import.meta.url);

let cached: { version: string; gitSha: string } | undefined;

export function scannerInfo(): { version: string; gitSha: string } {
  if (cached) return cached;
  const pkg = JSON.parse(readFileSync(new URL('package.json', ROOT), 'utf8')) as { version: string };
  let gitSha = process.env.NOIP_GIT_SHA ?? '';
  if (!gitSha) {
    try {
      const built = (JSON.parse(readFileSync(new URL('dist/build-info.json', ROOT), 'utf8')) as { gitSha: string }).gitSha;
      if (built && built !== 'unknown') gitSha = built;
    } catch {
      /* not a built tree */
    }
  }
  if (!gitSha) {
    try {
      gitSha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
    } catch {
      gitSha = 'unknown';
    }
  }
  cached = { version: pkg.version, gitSha };
  return cached;
}
