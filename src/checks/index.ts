import { namespaceChecks } from './namespace.js';
import { networkChecks } from './network.js';
import { podChecks } from './pod.js';
import { rbacChecks } from './rbac.js';
import type { Check } from './types.js';

/** Registry. Capped at ~15 checks by design (ADR-0004); wrap kube-bench/kubescape rather than grow this. */
export const ALL_CHECKS: readonly Check[] = [...podChecks, ...namespaceChecks, ...networkChecks, ...rbacChecks];

export type { Check, CheckContext, RawFinding } from './types.js';
export { SYSTEM_NAMESPACES } from './types.js';
