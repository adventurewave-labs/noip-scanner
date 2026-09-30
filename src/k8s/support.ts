/**
 * Upstream Kubernetes support status for the scanned control plane: a report *fact*, not a check,
 * so it never changes the score or uses one of the 15 check slots (ADR-0004).
 *
 * Source: https://kubernetes.io/releases (end-of-life dates and latest patches), captured 2026-09-26.
 * Managed platforms (EKS, GKE, AKS, LKE…) publish their own, often longer, schedules; the report says so.
 * Refresh this table when upstream cuts a minor release.
 */
export const SUPPORT_TABLE_AS_OF = '2026-09-26';
export const SUPPORT_SOURCE = 'https://kubernetes.io/releases';

/** minor -> [end of life (YYYY-MM-DD), latest patch at SUPPORT_TABLE_AS_OF] */
export const UPSTREAM: Record<string, [string, string]> = {
  '1.37': ['2027-10-28', '1.37.0'],
  '1.36': ['2027-06-28', '1.36.4'],
  '1.35': ['2027-02-28', '1.35.8'],
  '1.34': ['2026-10-27', '1.34.11'],
  '1.33': ['2026-06-28', '1.33.13'],
  '1.32': ['2026-02-28', '1.32.13'],
  '1.31': ['2025-11-11', '1.31.14'],
  '1.30': ['2025-07-15', '1.30.14'],
  '1.29': ['2025-02-28', '1.29.14'],
  '1.28': ['2024-10-22', '1.28.15'],
  '1.27': ['2024-07-16', '1.27.16'],
  '1.26': ['2024-02-28', '1.26.15'],
  '1.25': ['2023-10-28', '1.25.16'],
  '1.24': ['2023-07-28', '1.24.17'],
};

export interface VersionSupport {
  minor: string;
  status: 'supported' | 'ending-soon' | 'end-of-life' | 'unknown';
  endOfLife?: string;
  daysLeft?: number;
  latestPatch?: string;
  patchBehind: boolean;
  asOf: string;
  source: string;
}

const ENDING_SOON_DAYS = 90;

/** Parse `v1.31.4`, `v1.31.4-eks-1234`, `v1.30.2+k3s1`, `1.29.0-gke.100`. */
export function parseVersion(gitVersion: string): { minor: string; patch: number } | undefined {
  const m = /^v?(\d+)\.(\d+)\.(\d+)/.exec(gitVersion.trim());
  return m ? { minor: `${m[1]}.${m[2]}`, patch: Number(m[3]) } : undefined;
}

export function versionSupport(gitVersion: string, today: Date = new Date()): VersionSupport | undefined {
  const v = parseVersion(gitVersion);
  if (!v) return undefined; // e.g. manifest scans ("n/a")
  const base = { minor: v.minor, asOf: SUPPORT_TABLE_AS_OF, source: SUPPORT_SOURCE };
  const row = UPSTREAM[v.minor];
  if (!row) {
    // Older than the table: long out of support. Newer than the table: unknown until the table is refreshed.
    const older = Number(v.minor.split('.')[1]) < 24 && v.minor.startsWith('1.');
    return older ? { ...base, status: 'end-of-life', patchBehind: false } : { ...base, status: 'unknown', patchBehind: false };
  }
  const [eol, latest] = row;
  const daysLeft = Math.floor((Date.parse(`${eol}T00:00:00Z`) - Date.parse(today.toISOString().slice(0, 10) + 'T00:00:00Z')) / 86_400_000);
  const status = daysLeft < 0 ? 'end-of-life' : daysLeft <= ENDING_SOON_DAYS ? 'ending-soon' : 'supported';
  return { ...base, status, endOfLife: eol, daysLeft, latestPatch: latest, patchBehind: v.patch < Number(latest.split('.')[2]) };
}
