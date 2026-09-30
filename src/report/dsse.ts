import { createHash, createPrivateKey, createPublicKey, sign, verify, type KeyObject } from 'node:crypto';

/**
 * DSSE (Dead Simple Signing Envelope, https://github.com/secure-systems-lab/dsse) for the bundle's in-toto
 * statement. Keys are the operator's own PEM files (Ed25519 or ECDSA P-256); NOIP never generates or stores keys.
 * The signature covers PAE(payloadType, payload), per the DSSE v1 spec.
 */
export const DSSE_FILE = 'provenance.intoto.dsse.json';
export const INTOTO_PAYLOAD_TYPE = 'application/vnd.in-toto+json';

export interface Envelope {
  payloadType: string;
  payload: string; // base64
  signatures: Array<{ keyid: string; sig: string }>;
}

/** DSSE v1 pre-authentication encoding. Lengths are byte lengths. */
export function pae(payloadType: string, payload: Buffer): Buffer {
  const t = Buffer.from(payloadType, 'utf8');
  return Buffer.concat([Buffer.from(`DSSEv1 ${t.length} `), t, Buffer.from(` ${payload.length} `), payload]);
}

function algorithm(key: KeyObject): 'ed25519' | 'sha256' {
  if (key.asymmetricKeyType === 'ed25519') return 'ed25519';
  if (key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails?.namedCurve === 'prime256v1') return 'sha256';
  throw new Error(`unsupported signing key (${key.asymmetricKeyType}${key.asymmetricKeyDetails?.namedCurve ? ` ${key.asymmetricKeyDetails.namedCurve}` : ''}); use Ed25519 or ECDSA P-256`);
}

/** keyid: SHA-256 of the public key's DER SubjectPublicKeyInfo, hex. Informational; verification uses the key given. */
export const keyId = (pub: KeyObject) => createHash('sha256').update(pub.export({ type: 'spki', format: 'der' })).digest('hex');

export function signEnvelope(payload: Buffer, privateKeyPem: string, payloadType = INTOTO_PAYLOAD_TYPE): Envelope {
  const key = createPrivateKey(privateKeyPem);
  const alg = algorithm(key);
  const sig = sign(alg === 'ed25519' ? null : 'sha256', pae(payloadType, payload), key);
  return { payloadType, payload: payload.toString('base64'), signatures: [{ keyid: keyId(createPublicKey(key)), sig: sig.toString('base64') }] };
}

/** Returns the verified payload, or throws with the reason. At least one signature must verify with the given key. */
export function verifyEnvelope(env: Envelope, publicKeyPem: string): Buffer {
  const key = createPublicKey(publicKeyPem);
  const alg = algorithm(key);
  if (typeof env?.payload !== 'string' || typeof env.payloadType !== 'string' || !Array.isArray(env.signatures)) throw new Error('not a DSSE envelope');
  const payload = Buffer.from(env.payload, 'base64');
  const msg = pae(env.payloadType, payload);
  const ok = env.signatures.some((s) => typeof s?.sig === 'string' && verify(alg === 'ed25519' ? null : 'sha256', msg, key, Buffer.from(s.sig, 'base64')));
  if (!ok) throw new Error('no signature verifies with the given public key');
  return payload;
}
