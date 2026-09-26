import type { V1Pod } from '@kubernetes/client-node';
import { containersOf, workloadOf } from '../checks/workload.js';
import { resourceKey } from '../scan.js';
import type { Report } from '../types.js';
import { uuidv5 } from './oscal.js';

/**
 * KBOM: a Kubernetes bill of materials as CycloneDX 1.6 JSON. The cluster is the `platform` component;
 * each distinct container image in scope is a `container` component with the workloads and namespaces
 * that run it. Image references come from pod specs as written (tags are not resolved to digests).
 * Validated in tests against the official CycloneDX 1.6 schema (schemas/vendor/).
 */
export interface ImageUse {
  image: string;
  /** Distinct workloads (replicas collapse) running this image, in any container type. */
  workloads: number;
  namespaces: string[];
}

/** Pure: image inventory from pods in scope. */
export function imageInventory(pods: V1Pod[], excluded: ReadonlySet<string>): ImageUse[] {
  const by = new Map<string, { workloads: Set<string>; namespaces: Set<string> }>();
  for (const p of pods) {
    const ns = p.metadata?.namespace ?? 'default';
    if (excluded.has(ns)) continue;
    const w = resourceKey(workloadOf(p));
    for (const { container } of containersOf(p)) {
      if (!container?.image) continue;
      const e = by.get(container.image) ?? { workloads: new Set<string>(), namespaces: new Set<string>() };
      e.workloads.add(w);
      e.namespaces.add(ns);
      by.set(container.image, e);
    }
  }
  return [...by.entries()]
    .map(([image, e]) => ({ image, workloads: e.workloads.size, namespaces: [...e.namespaces].sort() }))
    .sort((a, b) => a.image.localeCompare(b.image));
}

export interface ImageRef {
  registry: string;
  repository: string;
  tag?: string;
  digest?: string;
}

/** Parse `[registry/]repo[:tag][@sha256:…]` with Docker's defaults (docker.io, library/, no implied tag). */
export function parseImage(ref: string): ImageRef {
  let rest = ref.trim();
  let digest: string | undefined;
  const at = rest.indexOf('@');
  if (at >= 0) {
    digest = rest.slice(at + 1);
    rest = rest.slice(0, at);
  }
  let tag: string | undefined;
  const colon = rest.lastIndexOf(':');
  if (colon > rest.lastIndexOf('/')) {
    tag = rest.slice(colon + 1);
    rest = rest.slice(0, colon);
  }
  const parts = rest.split('/');
  const first = parts[0]!;
  const hasRegistry = parts.length > 1 && (first.includes('.') || first.includes(':') || first === 'localhost');
  const registry = hasRegistry ? first : 'docker.io';
  let repository = hasRegistry ? parts.slice(1).join('/') : rest;
  if (registry === 'docker.io' && !repository.includes('/')) repository = `library/${repository}`;
  return { registry, repository, ...(tag ? { tag } : {}), ...(digest ? { digest } : {}) };
}

const SHA256 = /^sha256:[a-f0-9]{64}$/;

/** Package URL for an OCI image; per the purl spec the version must be a digest, so only pinned images get one. */
function purl(i: ImageRef): string | undefined {
  if (!SHA256.test(i.digest ?? '')) return undefined;
  const name = i.repository.split('/').pop()!.toLowerCase();
  const q = new URLSearchParams({ repository_url: `${i.registry}/${i.repository}`.toLowerCase(), ...(i.tag ? { tag: i.tag } : {}) });
  return `pkg:oci/${name}@${encodeURIComponent(i.digest!)}?${q.toString()}`;
}

export function renderKbom(r: Report): object {
  const images = r.inventory?.images ?? [];
  const seed = `${r.source}|${r.provenance.cluster.context ?? ''}|${r.provenance.scannedAt}|${r.provenance.scanner.gitSha}`;
  const platformRef = 'cluster';
  const prop = (name: string, value: string) => ({ name: `noip:${name}`, value });
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${uuidv5(`${seed}|kbom`)}`,
    version: 1,
    metadata: {
      timestamp: r.provenance.scannedAt,
      tools: { components: [{ type: 'application', name: 'noip', version: r.provenance.scanner.version, properties: [prop('gitSha', r.provenance.scanner.gitSha)] }] },
      component: {
        type: 'platform',
        'bom-ref': platformRef,
        name: r.provenance.cluster.context ?? (r.source === 'manifests' ? 'manifests' : 'kubernetes'),
        ...(r.provenance.cluster.serverVersion && r.provenance.cluster.serverVersion !== 'n/a' ? { version: r.provenance.cluster.serverVersion } : {}),
        properties: [
          prop('source', r.source),
          prop('nodeCount', String(r.provenance.cluster.nodeCount)),
          ...(r.provenance.cluster.versionSupport ? [prop('kubernetesSupport', r.provenance.cluster.versionSupport.status)] : []),
        ],
      },
      properties: [prop('scope', `excluded namespaces: ${r.provenance.excludedNamespaces.join(', ') || 'none'}`)],
    },
    components: images.map((u) => {
      const ref = parseImage(u.image);
      const p = purl(ref);
      return {
        type: 'container',
        'bom-ref': `image:${u.image}`,
        name: `${ref.registry}/${ref.repository}`,
        ...(ref.digest ? { version: ref.digest } : ref.tag ? { version: ref.tag } : {}),
        ...(p ? { purl: p } : {}),
        ...(SHA256.test(ref.digest ?? '') ? { hashes: [{ alg: 'SHA-256', content: ref.digest!.slice(7) }] } : {}),
        properties: [
          prop('imageReference', u.image),
          prop('pinnedByDigest', String(Boolean(ref.digest))),
          prop('workloads', String(u.workloads)),
          prop('namespaces', u.namespaces.join(',')),
        ],
      };
    }),
    dependencies: [{ ref: platformRef, dependsOn: images.map((u) => `image:${u.image}`) }],
  };
}
