/** Raised whenever the Kubernetes API cannot be reached or refuses a read. Never silently replaced by fixture data. */
export class K8sUnavailable extends Error {
  readonly code = 'K8sUnavailable';
  constructor(
    message: string,
    readonly httpStatus?: number,
  ) {
    super(message);
    this.name = 'K8sUnavailable';
  }
}

export class LLMNotConfigured extends Error {
  readonly code = 'LLMNotConfigured';
  constructor(message = 'No LLM provider key configured (set ANTHROPIC_API_KEY or NOIP_LLM_API_KEY).') {
    super(message);
    this.name = 'LLMNotConfigured';
  }
}
