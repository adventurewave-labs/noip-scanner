# Pod Security Admission conformance fixtures

Copied unmodified from [kubernetes/pod-security-admission](https://github.com/kubernetes/pod-security-admission) `test/testdata/`
(commit `fdf93707c97ded0c6e1b0ff8284cfc4f611d7a25`), for policy versions 1.23, 1.25, 1.30, 1.34, 1.35 and 1.37.
Licensed under the Apache License 2.0 (see `LICENSE` in this folder). `test/psa.test.ts` requires `src/psa.ts` to
admit every `pass` pod and reject every `fail` pod at the matching level and version.
