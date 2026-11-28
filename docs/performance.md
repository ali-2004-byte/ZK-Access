# Groth16 Proof Performance Report (B4 / T3)

This report records repeatable proof generation, verification, and proof size measurements for `circuits/age18.circom` (`age18-groth16-v1`).

## Environment

- **Timestamp (UTC):** `2026-11-28T07:36:14.446Z`
- **Node.js:** `v24.18.0` (`win32` / `x64`)
- **CPU:** `Intel(R) Core(TM) i7-8650U CPU @ 1.90GHz` (8 logical cores)
- **RAM:** 32,602 MB
- **Prover / Verifier:** `snarkjs` `0.7.6` (`groth16.fullProve` with `{ singleThread: true }`, `verifyAgeProof` from `src/app/proof-engine.mjs`)

## Methodology

- **Command:** `npm run zk:bench -- --write` (`node scripts/zk-benchmark.mjs --write`)
- **Fixtures:** Synthetic `birthDate` (`20081109`), `cutoff` (`20081109`), synthetic `salt`, and synthetic 248-bit `challengeHash` per sample. No real personal data is used.
- **Warm-up handling:** 2 unmeasured warm-up runs are executed before the 10 measured runs to initialize V8 JIT and snarkjs's `curve_bn128` WebAssembly state.
- **Sample count:** 10 measured runs (`samples: 10`).
- **Raw results:** Stored in [zk-benchmark-results.json](benchmarks/zk-benchmark-results.json).

## Summary Statistics

| Metric | Min | Median | Mean | Max |
| --- | --- | --- | --- | --- |
| Proof generation time (ms) | 611.38 | 623.10 | 623.78 | 636.67 |
| Verification time (ms) | 14.97 | 21.10 | 20.52 | 25.63 |
| Proof JSON size (bytes) | 720 | 723.00 | 723.20 | 726 |
| Public signals JSON size (bytes) | 247 | 249.00 | 248.90 | 250 |

## Limitations of Local Measurements

- Measurements were collected on a single developer laptop in Node.js (`singleThread: true`), not inside a browser tab; browser WASM execution, WebWorker startup, and artifact download (`age18.wasm` + `age18_final.zkey`) add initial latency on the first proof.
- `verificationMs` measures `verifyAgeProof` alone; end-to-end HTTP `POST /api/verifications` latency (`decisionLatencyMs`) also includes strict JSON parsing, Ed25519 signature verification, loopback issuer status lookup, and SQLite transaction commit.
- Timing varies with CPU load, power management, and hardware; these numbers establish a local baseline for the classroom demo rather than a production SLA.
