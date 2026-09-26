import { generateKeyPairSync, createPublicKey, verify } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EXIT, main } from '../src/cli.js';
import { verifyBundle, writeBundle, STATEMENT_FILE } from '../src/report/bundle.js';
import { DSSE_FILE, pae, signEnvelope, verifyEnvelope, type Envelope } from '../src/report/dsse.js';
import { buildReport, loadDemoSnapshot } from '../src/scan.js';

const pem = (type: 'ed25519' | 'ec' | 'rsa') => {
  const k =
    type === 'ec'
      ? generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
      : type === 'rsa'
        ? generateKeyPairSync('rsa', { modulusLength: 2048 })
        : generateKeyPairSync('ed25519');
  return { priv: k.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string, pub: k.publicKey.export({ type: 'spki', format: 'pem' }) as string };
};
const tmp = () => mkdtempSync(join(tmpdir(), 'noip-dsse-'));
const report = () => buildReport(loadDemoSnapshot(), 'demo', { now: new Date('2026-09-26T00:00:00Z') });

describe('DSSE', () => {
  it('PAE matches the DSSE v1 spec encoding', () => {
    expect(pae('http://example.com/HelloWorld', Buffer.from('hello world')).toString()).toBe('DSSEv1 29 http://example.com/HelloWorld 11 hello world');
    // byte lengths, not string lengths
    expect(pae('t', Buffer.from('é')).toString()).toBe('DSSEv1 1 t 2 é');
  });

  for (const type of ['ed25519', 'ec'] as const) {
    it(`signs and verifies with ${type}; the signature is over PAE, checkable with plain crypto`, () => {
      const { priv, pub } = pem(type);
      const env = signEnvelope(Buffer.from('{"a":1}'), priv);
      expect(verifyEnvelope(env, pub).toString()).toBe('{"a":1}');
      const ok = verify(type === 'ed25519' ? null : 'sha256', pae(env.payloadType, Buffer.from('{"a":1}')), createPublicKey(pub), Buffer.from(env.signatures[0]!.sig, 'base64'));
      expect(ok).toBe(true);
      expect(env.signatures[0]!.keyid).toMatch(/^[0-9a-f]{64}$/);
      expect(() => verifyEnvelope({ ...env, payload: Buffer.from('{"a":2}').toString('base64') }, pub)).toThrow(/no signature verifies/);
      expect(() => verifyEnvelope(env, pem(type).pub)).toThrow(/no signature verifies/);
    });
  }

  it('rejects unsupported keys and malformed envelopes', () => {
    expect(() => signEnvelope(Buffer.from('x'), pem('rsa').priv)).toThrow(/unsupported signing key \(rsa\)/);
    const p384 = generateKeyPairSync('ec', { namedCurve: 'secp384r1' }).privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
    expect(() => signEnvelope(Buffer.from('x'), p384)).toThrow(/secp384r1/);
    expect(() => verifyEnvelope({} as Envelope, pem('ed25519').pub)).toThrow(/not a DSSE envelope/);
  });
});

describe('signed evidence bundles', () => {
  it('writes a DSSE envelope over the exact statement bytes; verify-bundle checks it with the key', () => {
    const { priv, pub } = pem('ec');
    const d = tmp();
    writeBundle(d, report(), 'en', { signKeyPem: priv });
    const env = JSON.parse(readFileSync(join(d, DSSE_FILE), 'utf8')) as Envelope;
    expect(Buffer.from(env.payload, 'base64').equals(readFileSync(join(d, STATEMENT_FILE)))).toBe(true);
    expect(verifyBundle(d)).toMatchObject({ ok: true, signature: 'unverified' });
    expect(verifyBundle(d, { publicKeyPem: pub })).toMatchObject({ ok: true, signature: 'verified', files: 8 });
    expect(verifyBundle(d, { publicKeyPem: pem('ec').pub })).toMatchObject({ ok: false, problems: ['signature: no signature verifies with the given public key'] });
  });

  it('catches a re-signed or swapped statement and a wrong payload type', () => {
    const { priv, pub } = pem('ed25519');
    const d = tmp();
    writeBundle(d, report(), 'en', { signKeyPem: priv });
    // attacker re-signs a different payload with their key and fixes up SHA256SUMS: our key rejects it
    const env = JSON.parse(readFileSync(join(d, DSSE_FILE), 'utf8')) as Envelope;
    const other = signEnvelope(Buffer.from('{}'), priv);
    writeFileSync(join(d, DSSE_FILE), JSON.stringify({ ...env, payload: other.payload, signatures: other.signatures }));
    const v = verifyBundle(d, { publicKeyPem: pub });
    expect(v.problems).toEqual(expect.arrayContaining(['hash mismatch: provenance.intoto.dsse.json', 'signature: signed payload differs from provenance.intoto.json']));
    writeFileSync(join(d, DSSE_FILE), JSON.stringify({ ...env, payloadType: 'text/plain' }));
    expect(verifyBundle(d, { publicKeyPem: pub }).problems).toContain('signature: payloadType is text/plain, expected application/vnd.in-toto+json');
    const unsigned = tmp();
    writeBundle(unsigned, report());
    expect(verifyBundle(unsigned, { publicKeyPem: pub }).problems).toEqual(['--key given but the bundle has no provenance.intoto.dsse.json']);
  });
});

describe('CLI: --sign-key / verify-bundle --key', () => {
  let err = '';
  beforeEach(() => {
    err = '';
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    vi.spyOn(process.stderr, 'write').mockImplementation((s) => ((err += String(s)), true));
  });
  afterEach(() => {
    vi.restoreAllMocks();
    process.exitCode = undefined;
  });
  it('signs, verifies, and refuses --sign-key without --bundle', async () => {
    const { priv, pub } = pem('ed25519');
    const dir = tmp();
    writeFileSync(join(dir, 'k.pem'), priv);
    writeFileSync(join(dir, 'p.pem'), pub);
    const b = join(dir, 'b');
    await main(['node', 'noip', 'scan', '--demo', '--bundle', b, '--sign-key', join(dir, 'k.pem')]);
    await main(['node', 'noip', 'verify-bundle', b]);
    expect(err).toContain('signature unverified');
    expect(err).toContain('pass --key');
    await main(['node', 'noip', 'verify-bundle', b, '--key', join(dir, 'p.pem')]);
    expect(err).toContain('signature verified');
    expect(process.exitCode ?? 0).toBe(0);
    await main(['node', 'noip', 'scan', '--demo', '--sign-key', join(dir, 'k.pem')]);
    expect(err).toContain('--sign-key needs --bundle');
    expect(process.exitCode).toBe(EXIT.ERROR);
  });
});
