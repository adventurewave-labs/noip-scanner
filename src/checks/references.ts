/**
 * Reference mappings from each check to two widely used guidance documents. Section names are cited
 * rather than page numbers so they survive re-issues. Like the SOC 2 / HIPAA mappings, these help an
 * auditor navigate; they are not an attestation of conformance.
 *
 * - NSA/CISA "Kubernetes Hardening Guide" (v1.2, Aug 2022)
 * - NIST SP 800-190 "Application Container Security Guide" (Sep 2017), section 4 risks
 */
export interface References {
  nsaCisa: string[];
  nist800190: string[];
}

const RUNTIME = '4.4.3 Insecure container runtime configurations';
const POD_SEC = 'Kubernetes Pod security';

export const REFERENCES: Record<string, References> = {
  'NOIP-POD-001': { nsaCisa: [POD_SEC], nist800190: [RUNTIME] },
  'NOIP-POD-002': { nsaCisa: [POD_SEC], nist800190: [RUNTIME] },
  'NOIP-POD-003': { nsaCisa: [POD_SEC], nist800190: [RUNTIME] },
  'NOIP-POD-004': { nsaCisa: [POD_SEC, 'Network separation and hardening'], nist800190: [RUNTIME, '4.4.2 Unbounded network access from containers'] },
  'NOIP-POD-005': { nsaCisa: [POD_SEC], nist800190: [RUNTIME] },
  'NOIP-POD-006': { nsaCisa: ['Non-root containers and "rootless" container engines'], nist800190: [RUNTIME] },
  'NOIP-POD-007': { nsaCisa: ['Immutable container file systems'], nist800190: [RUNTIME] },
  'NOIP-POD-008': { nsaCisa: ['Resource policies'], nist800190: [] },
  'NOIP-POD-009': { nsaCisa: ['Secrets'], nist800190: [] },
  'NOIP-NS-001': { nsaCisa: ['Pod security enforcement'], nist800190: [RUNTIME] },
  'NOIP-NET-001': { nsaCisa: ['Network policies'], nist800190: ['4.3.3 Poorly separated inter-container network traffic'] },
  'NOIP-NET-002': { nsaCisa: ['Network policies'], nist800190: ['4.4.2 Unbounded network access from containers'] },
  'NOIP-RBAC-001': { nsaCisa: ['Authentication and authorization'], nist800190: ['4.3.1 Unbounded administrative access', '4.3.2 Unauthorized access'] },
  'NOIP-RBAC-002': { nsaCisa: ['Authentication and authorization'], nist800190: ['4.3.1 Unbounded administrative access'] },
  'NOIP-RBAC-003': { nsaCisa: ['Authentication and authorization'], nist800190: ['4.3.2 Unauthorized access'] },
};

export const REFERENCE_SOURCES = {
  nsaCisa: 'NSA/CISA Kubernetes Hardening Guide v1.2',
  nist800190: 'NIST SP 800-190 Application Container Security Guide',
} as const;
