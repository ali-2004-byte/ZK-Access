# C4 classroom demo runbook

This is a 10–15 minute walkthrough on the `codex/member-c-browser-workflow` branch. Use synthetic dates and locally created accounts only. The browser journey still needs a rehearsal with real local sessions before its results can be used as final evidence.

## Prepare before presenting

1. From the repository root run `npm ci`, `npm run local:setup`, `npm run local:accounts`, and `npm test`. Enter the app-admin and issuer-admin usernames/passwords at the terminal prompt; do not put passwords in slides or reports.
2. Start `npm run start:app` and `npm run start:issuer` in separate terminals. Check `http://127.0.0.1:3000/health` and `http://127.0.0.1:3001/health`.
3. At the app sign-in page (`http://127.0.0.1:3000/`), the app admin creates one operator and one viewer account. Confirm the rule is minimum age 18 and note its actual version; do not assume it is version 1 after prior demonstrations.
4. At the separate issuer page (`http://127.0.0.1:3001/`), prepare two private JSON files: one for a clearly older adult (for example `2000-01-01` for a 2026 demo) and one for a minor (for example `2015-01-01`). Keep both active. Prepare a third birth date for someone who is 18 but not 19 on the demo's UTC date (for example `2008-01-01` on 2026-11-28); issue that credential live in step 1 below.
5. Keep app admin, operator, and viewer in separate browser profiles if available. Otherwise sign out and sign in between roles. The issuer login has its own cookie and can remain open on port 3001. Rehearse downloads and artifact loading once before the presentation.

## Live journey

| Time | Action | Expected evidence |
| --- | --- | --- |
| 0–1 min | Explain the claim: the operator proves an issuer-attested birth date meets the server's UTC age cutoff without sending birth date or salt to the app verifier. | Show the separate issuer and app addresses. |
| 1–2 min | Issuer admin enters the prepared 18-year-old synthetic birth date and clicks **Issue and download JSON**. Move that file to the operator browser. | Issuance list shows credential ID/status, not birth date or salt. |
| 2–4 min | Operator imports the file, clicks **Request challenge and prove**, and opens the result details. | `allow`, `PROOF_VALID`, fresh nonce, current rule/version, verification time, and proof size/timings. |
| 4–5 min | Operator clicks **Replay last proof**. | `deny`, `CHALLENGE_REPLAYED`, replayed nonce. A second use of the same challenge cannot allow. |
| 5–6 min | Operator imports the minor's private JSON and tries to prove. | Proof generation fails before submission because its birth date is after the cutoff. This does **not** create a verifier result row. |
| 6–8 min | App admin changes minimum age from 18 to 19. Operator imports the 18-year-old file again and tries to prove, then imports the older adult file and proves. | The 18-year-old witness now fails before submission. The older adult allows under the new rule version, which appears in history. |
| 8–9 min | Issuer admin revokes the older adult credential. Operator uses that file again with a new challenge. | Server records `deny` with `CREDENTIAL_REVOKED`; the issuer status check is independent of the proof. |
| 9–11 min | Viewer signs in and reads result history. In the viewer browser, open `http://127.0.0.1:3000/api/reports/export?format=json` directly, then return to the viewer page. | Viewer results have no timings or export control. Direct export attempt returns `AUTH_DENIED`, proving the permission is enforced by the server. |
| 11–13 min | Admin opens audit events; operator or admin exports JSON/CSV from the dashboard. Inspect one report. | Audit includes the denied viewer request and rule change. Report has safe reason codes and measurements, with no birth date, salt, commitment, or signature. |

## After the live sequence

- If the rule was raised to 19, restore it to 18 for the next run. The server requires confirmation when lowering the threshold; record the resulting rule version and audit event.
- Capture redacted screenshots of the allow, replay, revoked, viewer denial, rule change, audit event, and export. Record expected/actual result, evidence location, and pass/fail in [the test matrix](test-matrix.md).
- Keep the private credential JSON out of screenshots, exports, slides, and repository commits. The demo's local single-party Groth16 setup is not production-grade.

The UI replay button uses only the last **public** proof submission held in browser memory. It appears after a successful proof and sends the same submission once more. An issuer-outage retry is a separate button and uses the same unused challenge only while it remains valid.
