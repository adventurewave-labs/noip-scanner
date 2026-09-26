/** Structured JSON lines on stderr; stdout stays clean for CLI report output. */
type Level = 'debug' | 'info' | 'warn' | 'error';
const ORDER: Record<Level, number> = { debug: 10, info: 20, warn: 30, error: 40 };

export function log(level: Level, msg: string, fields: Record<string, unknown> = {}): void {
  const min = (process.env.NOIP_LOG_LEVEL as Level) ?? 'info';
  if (ORDER[level] < (ORDER[min] ?? 20)) return;
  process.stderr.write(JSON.stringify({ ts: new Date().toISOString(), level, msg, ...fields }) + '\n');
}
