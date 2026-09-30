# ADR-0003: LLM behind a provider seam, explanation only

- **Status:** accepted, 2026-09-25
- **Decides:** PRD §10 D3, R-6

The `LLMProvider.complete(prompt, schema)` interface has two adapters. `anthropic` is the default; its model is pinned once in `src/llm/provider.ts` and can be overridden with `NOIP_LLM_MODEL`. `openai-compatible` is a plain `fetch` adapter for OpenRouter, GLM, vLLM and similar. Switching providers requires only configuration changes.

The model's input is `llmPayload(report)`, which passes through `redact()`. Its output is zod-validated, and any priority citing an unknown finding ID is dropped. On any failure the result is `explanation: null`. The deterministic report is never modified by the LLM step.
