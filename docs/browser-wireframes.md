# Member C browser screens

The app uses separate pages for its admin, operator, and viewer roles. The issuer has its own page on the separate issuer service. All pages use the same visual language: a dark navigation rail, clear status cards, readable tables, and small charts derived only from sanitized results. Server endpoint permissions remain authoritative; hiding a control is not authorization.

## Routes and tasks

| Page | Main task | Data source |
| --- | --- | --- |
| App sign-in (`/`) | Sign in and open the page for the returned role | `POST /api/session/login`, `GET /api/session` |
| Operator (`/operator`) | Import private credential, request challenge, generate proof, inspect result/history, export | `POST /api/challenges`, `POST /api/verifications`, `GET /api/results`, `GET /api/reports/export` |
| Admin (`/admin`) | Review sanitized results, configure rules, inspect audit events, manage users, export | `GET /api/results`, `GET/PUT /api/rules`, `GET /api/audit-events`, user routes, export route |
| Viewer (`/viewer`) | Read all sanitized results and filter history | `GET /api/results`, `GET /api/results/:resultId` |
| Issuer (`http://127.0.0.1:3001/`) | Sign in, issue and download private credential JSON, review issuance metadata, revoke | Issuer session and credential routes |

## App page structure

```text
Role navigation: page title · signed-in role · logout
Summary: latest decisions · allow/deny counts · current task
Main task: role-specific form or read-only results
History: filters · result rows · selected result details
Feedback: safe reason code · next action · request status
```

The operator's proof area shows the imported credential ID and fixed issuer name, but never renders birth date, salt, commitment, or signature. The proof runs in browser memory. After verification, show decision, safe reason, rule/version, nonce status, verification time, expiry status, and permitted measurements. A challenge failure asks the operator to request another challenge; issuer unavailability explains that the same challenge remains retryable until expiry.

The admin's rule form displays current minimum age, challenge lifetime, and rule version. Lowering the age or lengthening the challenge requires an explicit confirmation step. The viewer has no proof, rule, audit, user-management, or export control; its result projection has no timings. Operator and admin can export the current result filter as JSON or CSV.

## States to show

| State | Screen response |
| --- | --- |
| Not signed in or expired session | Return to sign-in; do not retain private credential across page reload. |
| Normal allow | Clear allow status, safe evidence fields, timings for operator/admin. |
| Invalid/expired/revoked/replayed | Deny status with the fixed reason code and a next action. |
| Issuer unavailable | Deny status and explain retry before challenge expiry. |
| Malformed credential file | Reject before proving and explain the schema/4 KB limit without displaying private values. |
| Role denied | Show generic access denial; server writes the audit event. |
| Empty history or network failure | Distinct empty and retry states; never invent a result. |

Charts use the fetched sanitized result list only and label the displayed sample count; they are a visual summary, not a claim about the full database when the API's 500-row list limit applies. The final browser and accessibility smoke test belongs in C4.
