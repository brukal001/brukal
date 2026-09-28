# CoinDCX Bug Bounty Program

Welcome to the CoinDCX responsible disclosure program. Please read the scope and
rules below carefully before testing.

## Scope

| Asset | Type | Severity |
|---|---|---|
| coindcx.com | Domain | High |
| *.coindcx.com | Wildcard | High |
| api.coindcx.com | API | Critical |
| CoinDCX Android App (com.coindcx.app) | Android | High |
| CoinDCX iOS App (id1349116540) | iOS | High |
| staging.coindcx.com | Domain | Unclear |

## Out of Scope

- info.coindcx.com
- otcdesk.coindcx.com
- careers.coindcx.com
- coindcx.com/blog

## Qualifying vulnerabilities

- SQL Injection
- Cross-Site Scripting (XSS)
- Remote Code Execution
- IDOR
- SSRF
- CSRF
- Open Redirect
- Business Logic flaws

## Non-qualifying vulnerabilities

- Denial of Service (DoS) attacks

## Testing rules

- No automated scanners without prior written permission.
- This is a strictly read-only engagement; do not modify or delete any data.
- Please redact any PII you may encounter in reports and screenshots.
- Rate limit yourself; no high-traffic or load testing.

## Accounts

- You may register a free test account at https://coindcx.com/signup.
