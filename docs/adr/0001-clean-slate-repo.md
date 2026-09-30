# ADR-0001: Clean-slate repository and positioning

- **Status:** accepted, 2026-09-25
- **Decides:** PRD §10 D1, and the choice of repository

## Context
The PRD's Phase 0 assumed the old `adventurewave-labs/NOIP` repository would be revived in place. That repo carries simulated services, a frozen auth stack with Mongo and Redis, six scheduled workflows, and a codebase that is unlikely to boot under ESM (PRD §2.4). Only three services contain real value: the security, compliance, and discovery Kubernetes calls.

## Decision
- Build the scanner in a new private repository, `adventurewave-labs/noip-scanner`. Port only the check logic, and rewrite it as pure functions over a single fetched snapshot (PRD §7.3).
- Keep the NOIP acronym and retitle the project **"Kubernetes posture scanner"** (D1 option b).
- Leave the old repository untouched as the archive. Nothing from it is frozen or carried over, including the auth stack, the Python scripts, dashboards, performance simulation, and PSP manifests. This makes PRD R-2 and R-11 hold by construction.

## Consequences
- PRD Phases 0–2 (truth run, cut, boot fixes) collapse into "never import the broken parts".
- Porting surfaced one bug, which is fixed here: the old CIS-5.1.1 check flagged `system:masters`. Every cluster has the built-in `cluster-admin` binding to `system:masters`, so that control always failed.
- The old repo's description and README should point at this one. That is a manual step for the owner.
