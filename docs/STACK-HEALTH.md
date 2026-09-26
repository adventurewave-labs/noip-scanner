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
