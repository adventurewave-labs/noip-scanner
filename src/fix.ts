import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { isMap, isSeq, parseAllDocuments, type Document } from 'yaml';
import { listFiles, loadManifests } from './manifests.js';
import type { PatchOp } from './remediation.js';
import { buildReport, type ScanOptions } from './scan.js';
import type { Finding } from './types.js';

/**
 * `noip fix`: apply the deterministic patches from a manifest scan back onto the YAML, preserving
 * comments, ordering and unrelated documents. Writes to --out-dir by default; --in-place is explicit.
 */
export interface FixResult {
  applied: Array<{ findingId: string; file: string; description: string }>;
  advisory: Finding[];
  filesWritten: string[];
}

const segments = (pointer: string) =>
  pointer
    .split('/')
    .slice(1)
    .map((s) => s.replace(/~1/g, '/').replace(/~0/g, '~'))
    .map((s) => (/^\d+$/.test(s) ? Number(s) : s));

function objectKey(o: { kind?: string; metadata?: { name?: string; namespace?: string } }): string {
  const clusterScoped = o.kind === 'Namespace' || o.kind === 'ClusterRoleBinding';
  return clusterScoped ? `${o.kind}/${o.metadata?.name}` : `${o.kind}/${o.metadata?.namespace ?? 'default'}/${o.metadata?.name}`;
}

/** Find where an object lives inside a document (top level, or items[i] of a List). */
/** Index every object in a file once: key -> (document, path to the object). First declaration wins. */
function indexDocs(list: Document[]): Map<string, { doc: Document; base: Array<string | number> }> {
  const index = new Map<string, { doc: Document; base: Array<string | number> }>();
  const put = (key: string, v: { doc: Document; base: Array<string | number> }) => void (index.has(key) || index.set(key, v));
  for (const doc of list) {
    const js = doc.toJS() as { kind?: string; items?: Array<{ kind?: string; metadata?: { name?: string; namespace?: string } }> } | null;
    if (!js) continue;
    if (Array.isArray(js.items) && isMap(doc.contents) && isSeq(doc.contents.get('items', true))) js.items.forEach((it, i) => it && put(objectKey(it), { doc, base: ['items', i] }));
    else put(objectKey(js as never), { doc, base: [] });
  }
  return index;
}

function apply(doc: Document, base: Array<string | number>, op: PatchOp): void {
  const path = [...base, ...segments(op.path)];
  if (op.op === 'remove') doc.deleteIn(path);
  else doc.setIn(path, op.value);
}

export async function fixManifests(paths: string[], opts: ScanOptions & { outDir?: string; inPlace?: boolean; cwd?: string } = {}): Promise<FixResult> {
  if (paths.includes('-')) throw new Error('noip fix needs files, not stdin');
  if (!opts.outDir === !opts.inPlace) throw new Error('choose exactly one of --out-dir <dir> or --in-place');
  const cwd = opts.cwd ?? process.cwd();
  if (opts.outDir) {
    const out = resolve(cwd, opts.outDir);
    const inside = paths.map((p) => resolve(cwd, p)).find((p) => out === p || out.startsWith(p + sep));
    if (inside) throw new Error(`--out-dir ${opts.outDir} is inside the input ${relative(cwd, inside) || '.'}; choose a directory outside it`);
  }
  const report = buildReport(await loadManifests(paths.map((p) => resolve(cwd, p))), 'manifests', opts);

  const byFile = new Map<string, Finding[]>();
  const advisory: Finding[] = [];
  for (const f of report.findings) {
    if (f.fix && f.resource.source?.file) {
      const file = f.resource.source.file;
      if (!byFile.has(file)) byFile.set(file, []);
      byFile.get(file)!.push(f);
    }
    else advisory.push(f);
  }

  const result: FixResult = { applied: [], advisory, filesWritten: [] };
  for (const [file, findings] of byFile) {
    // loadManifests records paths relative to the process cwd.
    const abs = isAbsolute(file) ? file : resolve(process.cwd(), file);
    const src = readFileSync(abs, 'utf8');
    const docs = parseAllDocuments(src);
    // Follow the file's own flow-collection style (`{ a: 1 }` vs `{a: 1}`) to keep diffs minimal.
    const padded = /[{[] \S/.test(src);
    const list = Array.isArray(docs) ? docs : [docs];
    const index = indexDocs(list); // one pass per file: lookups stay O(1) for files with thousands of objects
    for (const f of findings) {
      const key = [f.resource.kind, f.resource.namespace, f.resource.name].filter(Boolean).join('/');
      const hit = index.get(key);
      if (!hit) {
        // e.g. generateName objects: never drop a finding silently.
        advisory.push(f);
        continue;
      }
      for (const op of f.fix!.patch) apply(hit.doc, hit.base, op);
      result.applied.push({ findingId: f.id, file, description: f.fix!.description });
    }
    // Mirror the path relative to `cwd`; files outside it keep only their in-tree tail.
    const target = opts.inPlace ? abs : join(resolve(cwd, opts.outDir!), relative(cwd, abs).replace(/^(\.\.[/\\])+/, ''));
    mkdirSync(dirname(target), { recursive: true });
    // Keep the author's layout: no re-wrapping, compact flow collections, and exactly one `---` between documents.
    const out = list
      .map((d, i) => {
        const text = d.toString({ lineWidth: 0, flowCollectionPadding: padded });
        return i === 0 || text.startsWith('---') ? text : `---\n${text}`;
      })
      .join('');
    writeFileSync(target, out);
    result.filesWritten.push(target);
  }
  // In out-dir mode, mirror the untouched inputs too, so the output is a complete, scannable tree.
  if (opts.outDir) {
    const written = new Set(result.filesWritten);
    for (const p of paths) {
      for (const f of listFiles(resolve(cwd, p))) {
        const target = join(resolve(cwd, opts.outDir), relative(cwd, f).replace(/^(\.\.[/\\])+/, ''));
        if (written.has(target)) continue;
        mkdirSync(dirname(target), { recursive: true });
        copyFileSync(f, target);
      }
    }
  }
  return result;
}
