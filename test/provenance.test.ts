import { describe, expect, it, vi } from 'vitest';

describe('scannerInfo', () => {
  it('prefers NOIP_GIT_SHA, else build-info or git, and never returns empty', async () => {
    const prev = process.env.NOIP_GIT_SHA;
    try {
      vi.resetModules();
      process.env.NOIP_GIT_SHA = 'abc123';
      expect((await import('../src/report/provenance.js')).scannerInfo().gitSha).toBe('abc123');

      vi.resetModules();
      delete process.env.NOIP_GIT_SHA;
      const info = (await import('../src/report/provenance.js')).scannerInfo();
      expect(info.gitSha).toMatch(/^([0-9a-f]{40}|unknown)$/);
      expect(info.version).toMatch(/^\d+\.\d+\.\d+/);
    } finally {
      process.env.NOIP_GIT_SHA = prev;
      vi.resetModules();
    }
  });
});
