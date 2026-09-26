import { readFileSync } from 'node:fs';
import { isDemoMode } from '../scan.js';
import { log } from '../logger.js';
import { createApp } from './app.js';

// Prefer a mounted file (NOIP_API_TOKEN_FILE) so the token is not an environment variable (cf. check NOIP-POD-009).
const token = (process.env.NOIP_API_TOKEN_FILE ? readFileSync(process.env.NOIP_API_TOKEN_FILE, 'utf8') : (process.env.NOIP_API_TOKEN ?? '')).trim();
if (token.length < 16) {
  log('error', 'NOIP_API_TOKEN (or NOIP_API_TOKEN_FILE) must hold a random string of at least 16 characters; refusing to start.');
  process.exit(1);
}

const demo = isDemoMode();
const port = Number(process.env.PORT) || 3000;
const server = createApp({ token, demo, ignoreFile: process.env.NOIP_IGNORE_FILE || undefined }).listen(port, () => log('info', 'noip api listening', { port, mode: demo ? 'demo' : 'live' }));

for (const sig of ['SIGTERM', 'SIGINT'] as const) {
  process.on(sig, () => {
    log('info', 'shutting down', { signal: sig });
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5000).unref();
  });
}
