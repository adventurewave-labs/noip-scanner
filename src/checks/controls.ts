/**
 * CIS Kubernetes Benchmark (v1.9-era numbering) controls NOIP gathers evidence for.
 * SOC 2 / HIPAA identifiers are REFERENCE MAPPINGS to help an auditor navigate — not an attestation.
 */
export interface ControlDef {
  title: string;
  soc2: string[];
  hipaa: string[];
}

export const BENCHMARK = 'CIS Kubernetes Benchmark (Level 1, workload subset)';

export const CONTROLS: Record<string, ControlDef> = {
  'CIS-5.1.1': { title: 'cluster-admin role is only used where required', soc2: ['CC6.1', 'CC6.3'], hipaa: ['164.312(a)(1)'] },
  'CIS-5.1.5': { title: 'Default service accounts are not actively used', soc2: ['CC6.1', 'CC6.3'], hipaa: ['164.312(a)(1)'] },
  'CIS-5.2.1': { title: 'Minimize the admission of privileged containers', soc2: ['CC6.1', 'CC6.6'], hipaa: ['164.312(a)(1)', '164.312(c)(1)'] },
  'CIS-5.2.2': { title: 'Minimize containers sharing the host PID namespace', soc2: ['CC6.1'], hipaa: ['164.312(a)(1)'] },
  'CIS-5.2.3': { title: 'Minimize containers sharing the host IPC namespace', soc2: ['CC6.1'], hipaa: ['164.312(a)(1)'] },
  'CIS-5.2.4': { title: 'Minimize containers sharing the host network namespace', soc2: ['CC6.1', 'CC6.6'], hipaa: ['164.312(a)(1)'] },
  'CIS-5.2.5': { title: 'Minimize containers with allowPrivilegeEscalation', soc2: ['CC6.1', 'CC6.6'], hipaa: ['164.312(c)(1)'] },
  'CIS-5.2.6': { title: 'Minimize the admission of root containers', soc2: ['CC6.1'], hipaa: ['164.312(a)(1)'] },
  'CIS-5.3.2': { title: 'All namespaces have NetworkPolicies defined', soc2: ['CC6.6', 'CC6.7'], hipaa: ['164.312(a)(1)', '164.312(e)(1)'] },
  'CIS-5.4.1': { title: 'Prefer secrets as files over secrets as environment variables', soc2: ['CC6.1', 'CC6.7'], hipaa: ['164.312(a)(2)(iv)', '164.312(e)(2)(ii)'] },
};

export const MAPPING_DISCLAIMER =
  'SOC 2, HIPAA, NSA/CISA and NIST SP 800-190 identifiers are reference mappings, not an attestation. NOIP checks a workload subset of CIS Kubernetes Benchmark Level 1 and does not assess control-plane, node or process controls.';
