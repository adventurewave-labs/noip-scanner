import { readFileSync, readdirSync, statSync } from 'node:fs';
import { extname, join, relative } from 'node:path';
import type {
  V1ClusterRoleBinding,
  V1Namespace,
  V1NetworkPolicy,
  V1ObjectMeta,
  V1Pod,
  V1PodTemplateSpec,
  V1RoleBinding,
} from '@kubernetes/client-node';
import { isMap, isSeq, LineCounter, parseAllDocuments, type Node as YamlNode } from 'yaml';
import type { ClusterSnapshot } from './types.js';

/**
 * Shift-left: build the same ClusterSnapshot the live fetcher produces, from YAML on disk or stdin
 * (plain manifests, `helm template` or `kustomize build` output). Checks run unchanged.
 */

interface K8sObject {
  apiVersion?: string;
  kind?: string;
  metadata?: V1ObjectMeta;
  spec?: Record<string, unknown>;
  items?: K8sObject[];
}

const YAML_EXT = new Set(['.yaml', '.yml', '.json']);
const WORKLOADS: Record<string, (spec: Record<string, unknown>) => V1PodTemplateSpec | undefined> = {
  Deployment: (s) => s.template as V1PodTemplateSpec,
  StatefulSet: (s) => s.template as V1PodTemplateSpec,
  DaemonSet: (s) => s.template as V1PodTemplateSpec,
  ReplicaSet: (s) => s.template as V1PodTemplateSpec,
  ReplicationController: (s) => s.template as V1PodTemplateSpec,
  Job: (s) => s.template as V1PodTemplateSpec,
  CronJob: (s) => ((s.jobTemplate as { spec?: { template?: V1PodTemplateSpec } } | undefined)?.spec?.template),
};

export function listFiles(path: string): string[] {
  const st = statSync(path);
  if (!st.isDirectory()) return [path];
  return readdirSync(path)
    .sort()
    .flatMap((e) => (e.startsWith('.') ? [] : listFiles(join(path, e))))
    .filter((f) => YAML_EXT.has(extname(f).toLowerCase()));
}

export class ManifestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ManifestError';
  }
}

/** Parse one YAML stream into objects with the 1-based line each object starts on. */
export function parseManifestText(text: string, file: string): Array<{ obj: K8sObject; line: number }> {
  const lc = new LineCounter();
  const docs = parseAllDocuments(text, { lineCounter: lc });
  const out: Array<{ obj: K8sObject; line: number }> = [];
  const lineOf = (n: YamlNode | null | undefined) => (n?.range ? lc.linePos(n.range[0]).line : 1);
  for (const doc of Array.isArray(docs) ? docs : [docs]) {
    if (doc.errors.length) throw new ManifestError(`${file}: ${doc.errors[0]!.message.split('\n')[0]}`);
    const obj = doc.toJS() as K8sObject | null;
    if (!obj || typeof obj !== 'object') continue;
    if (obj.kind === 'List' || (obj.kind?.endsWith('List') && Array.isArray(obj.items))) {
      const itemsNode = isMap(doc.contents) ? doc.contents.get('items', true) : undefined;
      (obj.items ?? []).forEach((item, i) => out.push({ obj: item, line: lineOf(isSeq(itemsNode) ? (itemsNode.items[i] as YamlNode) : doc.contents) }));
    } else {
      out.push({ obj, line: lineOf(doc.contents) });
    }
  }
  return out;
}

/** Turn a workload's pod template into a V1Pod owned by that workload, so findings attribute to it. */
function podFromTemplate(kind: string, meta: V1ObjectMeta, tpl: V1PodTemplateSpec): V1Pod {
  return {
    metadata: {
      ...tpl.metadata,
      name: meta.name,
      namespace: meta.namespace ?? 'default',
      ownerReferences: [{ apiVersion: 'apps/v1', kind, name: meta.name ?? 'unknown', uid: 'manifest', controller: true }],
    },
    spec: tpl.spec,
  };
}

export async function loadManifests(paths: string[], readStdin: () => Promise<string> = defaultStdin): Promise<ClusterSnapshot> {
  const snap: ClusterSnapshot = {
    serverVersion: { gitVersion: 'n/a' },
    context: `manifests:${paths.join(',')}`,
    nodeCount: 0,
    namespaces: [],
    pods: [],
    networkPolicies: [],
    clusterRoleBindings: [],
    roleBindings: [],
    sources: {},
  };
  const inputs: Array<{ file: string; text: string }> = [];
  for (const p of paths) {
    if (p === '-') inputs.push({ file: '<stdin>', text: await readStdin() });
    else {
      let files: string[];
      try {
        files = listFiles(p);
      } catch (err) {
        throw new ManifestError(`--manifests: cannot read ${p} (${(err as NodeJS.ErrnoException).code ?? (err as Error).message})`);
      }
      for (const f of files) inputs.push({ file: relative(process.cwd(), f) || f, text: readFileSync(f, 'utf8') });
    }
  }

  const seen = new Set<string>();
  for (const { file, text } of inputs) {
    for (const { obj, line } of parseManifestText(text, file)) {
      const kind = obj.kind ?? '';
      // generateName objects have no name until the API server assigns one; make each declaration distinct.
      const meta: V1ObjectMeta = obj.metadata?.name || !obj.metadata?.generateName ? (obj.metadata ?? {}) : { ...obj.metadata, name: `${obj.metadata.generateName}<generated:${file.replace(/[\\/]/g, '_')}:${line}>` };
      const ns = meta.namespace ?? 'default';
      const clusterScoped = kind === 'Namespace' || kind === 'ClusterRoleBinding';
      const key = clusterScoped ? `${kind}/${meta.name}` : `${kind}/${ns}/${meta.name}`;
      if (seen.has(key)) continue; // same object rendered twice (e.g. overlapping dirs): first declaration wins
      seen.add(key);
      snap.sources![key] = { file, line };

      if (kind === 'Namespace') snap.namespaces.push(obj as V1Namespace);
      else if (kind === 'Pod') snap.pods.push({ ...(obj as V1Pod), metadata: { ...meta, namespace: ns } });
      else if (kind === 'NetworkPolicy') snap.networkPolicies.push({ ...(obj as V1NetworkPolicy), metadata: { ...meta, namespace: ns } });
      else if (kind === 'ClusterRoleBinding') snap.clusterRoleBindings.push(obj as V1ClusterRoleBinding);
      else if (kind === 'RoleBinding') snap.roleBindings.push({ ...(obj as V1RoleBinding), metadata: { ...meta, namespace: ns } });
      else if (WORKLOADS[kind]) {
        const tpl = WORKLOADS[kind](obj.spec ?? {});
        if (tpl?.spec) snap.pods.push(podFromTemplate(kind, { ...meta, namespace: ns }, tpl));
      }
    }
  }
  return snap;
}

/* v8 ignore next 5 -- process.stdin glue; loadManifests is tested with an injected reader */
async function defaultStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString('utf8');
}
