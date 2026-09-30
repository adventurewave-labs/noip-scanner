import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { delimiter, join } from 'node:path';
import { KubeConfig } from '@kubernetes/client-node';
import { K8sUnavailable } from '../errors.js';

export interface KubeOptions {
  kubeconfig?: string;
  context?: string;
}

/** The single KubeConfig factory. Explicit file > in-cluster > $KUBECONFIG/~/.kube/config. */
export function loadKubeConfig(opts: KubeOptions = {}): KubeConfig {
  const kc = new KubeConfig();
  try {
    if (opts.kubeconfig) kc.loadFromFile(opts.kubeconfig);
    else if (process.env.KUBERNETES_SERVICE_HOST) kc.loadFromCluster();
    else {
      // loadFromDefault() silently falls back to http://localhost:8080; fail clearly instead.
      const candidates = process.env.KUBECONFIG ? process.env.KUBECONFIG.split(delimiter).filter(Boolean) : [join(homedir(), '.kube', 'config')];
      if (!candidates.some((f) => existsSync(f))) {
        throw new K8sUnavailable(`no kubeconfig found (${candidates.join(', ')}) and not running in-cluster`);
      }
      kc.loadFromDefault();
    }
  } catch (err) {
    if (err instanceof K8sUnavailable) throw err;
    throw new K8sUnavailable(`could not load kubeconfig: ${(err as Error).message}`);
  }
  if (opts.context) {
    if (!kc.getContextObject(opts.context)) throw new K8sUnavailable(`context "${opts.context}" not found in kubeconfig`);
    kc.setCurrentContext(opts.context);
  }
  if (!kc.getCurrentCluster()) throw new K8sUnavailable('kubeconfig has no current cluster');
  return kc;
}
