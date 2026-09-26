# Stack health: 2026-09-26

GitHub Actions has been blocked by the org's billing/spending limit since PR #9. To make sure merging PRs #1 → #20 in order can't break partway through, every branch head was checked in a **fresh git worktree**, the way CI would run it: `npm ci`, then typecheck, lint, doc-lint, unit tests with the coverage gate from a clean tree with no `dist/`, then build.

The base branch measured **85.76%** branch coverage, the same figure its last real CI run reported, so these numbers are what CI would see.

| Branch (PR) | Gates | Tests | Branch coverage (threshold) |
|---|---|---|---|
| build/initial-scanner (#1) | ✅ | 75 | 85.76% (85) |
| r1-sarif (#2) | ✅ | 81 | 85.71% (85) |
| r2-manifests (#3) | ✅ | 99 | 89.13% (88) |
| r3-suppressions (#4) | ✅ | 110 | 89.63% (89) |
| r4-mcp (#5) | ✅ | 117 | 90.82% (90) |
| r5-diff (#6) | ✅ | 124 | 91.25% (91) |
| r6-review-fixes (#7) | ✅ | 139 | 92.03% (92) |
| r7-psa (#8) | ✅ | 140 | 92.14% (92) |
| r8-supply-chain (#9) | ✅ | 140 | 92.14% (92) |
| r9-html (#10) | ✅ | 147 | 92.52% (92) |
| r10-bundle (#11) | ✅ | 153 | 92.79% (92) |
| r11-fix (#12) | ✅ | 159 | 92.78% (92) |
| r12-import-sarif (#13) | ✅ | 165 | 92.92% (92) |
| r13-multi-context (#14) | ✅ | 172 | 93.15% (93) |
| r14-scale (#15) | ✅ | 177 | 93.24% (93) |
| r15-property-tests (#16) | ✅ | 189 | 93.24% (93) |
| r16-openapi (#17) | ✅ | 196 | 93.24% (93) |
| r17-mappings (#18) | ✅ | 199 | 93.39% (93) |
| r18-review2-fixes (#19) | ✅ | 205 | 93.59% (93) |
| r19-wrapup (#20) | ✅ | 205 | 93.59% (93) |

No PR lowers a coverage threshold compared with its base, so the ratchet holds.

**Not yet verified for #9–#20:** the kind live-scan job, the Docker smoke job, and `npm audit signatures`. All three need GitHub Actions or a Docker host. `npm run ci:local` runs every other gate on any machine.

## Loop 3 (rounds 20–40, PRs #21–#41): 2026-09-26

Every branch head was checked again the same way: a fresh git worktree with no `dist/`, then typecheck, lint, doc-lint, unit tests with the coverage gate, then build. All 21 pass.

| Branch (PR) | Commit | Gates | Statements | Branches | Functions | Lines |
|---|---|---|---|---|---|---|
| r20-ci-local (#21) | `3c8d4d3` | ✅ | 99.28% | 93.59% | 100% | 99.61% |
| r21-exec-summary (#22) | `a52a2b4` | ✅ | 99.3% | 93.77% | 100% | 99.63% |
| r22-i18n-es (#23) | `320718c` | ✅ | 99.33% | 94.13% | 100% | 99.65% |
| r23-version-support (#24) | `1e29a20` | ✅ | 99.36% | 94.25% | 100% | 99.66% |
| r24-history (#25) | `e3dadf1` | ✅ | 99.43% | 94.4% | 100% | 99.7% |
| r25-policy (#26) | `904ca53` | ✅ | 99.45% | 94.75% | 100% | 99.71% |
| r26-distribution (#27) | `1504153` | ✅ | 99.45% | 94.75% | 100% | 99.71% |
| r27-review3 (#28) | `a04db7c` | ✅ | 99.46% | 94.66% | 100% | 99.71% |
| r28-psa-readiness (#29) | `ce89ecc` | ✅ | 99.47% | 95.23% | 100% | 99.74% |
| r29-oscal (#30) | `6592c33` | ✅ | 99.48% | 94.86% | 100% | 99.75% |
| r30-dsse (#31) | `651e58e` | ✅ | 99.49% | 95% | 100% | 99.75% |
| r31-metrics (#32) | `62f9c2b` | ✅ | 99.5% | 94.79% | 100% | 99.76% |
| r32-review4 (#33) | `5bbfaf7` | ✅ | 99.51% | 94.89% | 100% | 99.76% |
| r33-risk-chains (#34) | `ffb3476` | ✅ | 99.53% | 95.29% | 100% | 99.77% |
| r34-perf (#35) | `9dc39f4` | ✅ | 99.53% | 95.38% | 100% | 99.77% |
| r35-mcp-tools (#36) | `b9b5a88` | ✅ | 99.54% | 95.32% | 100% | 99.78% |
| r36-serviceaccounts (#37) | `d93293e` | ✅ | 99.54% | 95.29% | 100% | 99.78% |
| r37-review5 (#38) | `b700e13` | ✅ | 99.49% | 95.35% | 100% | 99.71% |
| r38-kbom (#39) | `deb28b1` | ✅ | 99.45% | 95.15% | 100% | 99.72% |
| r39-diff-context (#40) | `466b3fc` | ✅ | 99.46% | 95.14% | 100% | 99.72% |
| r40-llm-context (#41) | `2d47233` | ✅ | 99.46% | 95.1% | 100% | 99.72% |

After round 40 the tip has 329 tests. Round 41 raises the ratchet to statements 99, branches 94.5, functions 100 and lines 99. Every branch from round 28 onwards is above those figures.

**Still not verified for #9–#42:** the kind live-scan job (which now also applies the admission policies and needs the new `serviceaccounts` permission), the Docker smoke job, the `action-smoke` job and `npm audit signatures`. These need GitHub Actions or a Docker host. Some checks were done by hand instead:
- the pre-commit hook, end to end with pre-commit 4.6.2;
- the DSSE signatures, against cosign v2.6.5;
- the OSCAL and CycloneDX output, against their official schemas.
