# Local development setup

This repository currently has two Express entry points, the UTC age policy, issuer calendar-date encoding, server-side role rules, session lifetime rules, the Circom age circuit and Groth16 artifacts, and planning/test documents. The app and issuer processes expose health checks only. No credential issuance, authentication, browser proof-generation, or HTTP verification endpoint is active yet. The policy and proof modules are not yet wired to HTTP routes.

## Prerequisites

- Node.js 24 and npm (the current scaffold was tested with Node.js 24.19.0 and npm 11.17.0).
- A terminal in the repository root. Docker is not required.

## Run

1. Install locked dependencies with `npm ci`.
2. Run `npm test`.
3. Run `npm run zk:setup` to verify the checked-in proof artifacts against the circuit. On a first build, this command downloads and checks the official Circom 2.2.3 binary, then runs a local single-party ceremony. Run `npm run zk:check` for a synthetic valid/invalid proof check.
4. In one terminal, run `npm run start:app`.
5. In another terminal, run `npm run start:issuer`.
6. Check `http://127.0.0.1:3000/health` and `http://127.0.0.1:3001/health`.

The services bind to loopback only. Set `APP_PORT` or `ISSUER_PORT` if those ports are occupied. The issuer and app must remain separate processes; the issuer's signing key and administrator login will be added to the issuer process only.

## Contributor entry points

- Member A: app and issuer service contracts, SQLite data model, cookie sessions, authorization, audit and export.
- Member B: Circom circuit, Groth16 artifacts, browser proof inputs, verification, and fixtures.
- Member C: plain JavaScript browser workflow, dashboard, report view, and integration.
- Member D: threat model, misuse tests, performance measurements, packaging, and clean install rehearsal.

Existing policy code lives in `src/age-policy.mjs`, `src/issuer/birth-date.mjs`, `src/app/access-policy.mjs`, and `src/app/session-policy.mjs`. `npm test` checks age boundaries, issuer calendar validation and YYYYMMDD encoding, cross-role denials, session deadlines, and challenge issuance near session expiry.

Read the [implementation plan](implementation-plan.md), [work packages](work-packages.md), and [test matrix](test-matrix.md) before changing interfaces. The agreed role and output rules are in the implementation plan.
