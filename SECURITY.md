# Security Policy

## Supported Versions

Only the versions listed below receive security updates. If you are running an older version, please upgrade immediately.

| Version | Supported          |
|---------|--------------------|
| 3.x (Phantom Strike) | ✅ Active support |
| 2.x     | ⚠️ Critical fixes only (until 2025-12-31) |
| < 2.0   | ❌ End of life — no longer supported |

---

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.** Doing so puts all users at risk before a fix is available.

### Preferred Channel — GitHub Private Security Advisories

1. Navigate to the [Security Advisories](https://github.com/basithpi/owasp-sentinel/security/advisories) tab.
2. Click **"New draft security advisory"**.
3. Fill in as much detail as possible (see template below).
4. Submit the draft — only you and repository maintainers can see it.

### Alternative Channel — Email

If you cannot use GitHub Advisories, send an encrypted email to:

**security@sentinel.example.com**

PGP fingerprint: `ABCD 1234 EFGH 5678 IJKL  9012 MNOP 3456 QRST 7890`  
Public key: [https://sentinel.example.com/.well-known/security.asc](https://sentinel.example.com/.well-known/security.asc)

---

## What to Include in Your Report

Please provide as much of the following as possible to help us triage quickly:

- **Summary:** A one-sentence description of the vulnerability.
- **Affected component:** (e.g., authentication module, report upload endpoint, Celery task handler)
- **Severity:** Your assessment (Critical / High / Medium / Low) and any applicable CVSS score.
- **CVE / CWE:** If you have already identified one.
- **Steps to reproduce:** A minimal, step-by-step procedure to trigger the vulnerability.
- **Proof of concept:** Code snippet, screenshot, or video demonstrating the issue.
- **Impact:** What an attacker could achieve by exploiting this vulnerability.
- **Suggested fix:** (optional) Any ideas you have for remediation.
- **Disclosure preference:** Whether you want to be credited and, if so, how.

---

## Disclosure Timeline

We aim to follow [responsible disclosure](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html) best practices:

| Milestone | Target Timeframe |
|-----------|-----------------|
| Initial acknowledgement | Within **48 hours** of report |
| Triage & severity assessment | Within **5 business days** |
| Fix developed (critical/high) | Within **14 calendar days** |
| Fix developed (medium/low) | Within **30 calendar days** |
| Patch released & advisory published | Within **7 days** of fix being merged |
| Researcher credit (with consent) | At time of advisory publication |

If we cannot meet a deadline, we will communicate proactively with the reporter.

For critical vulnerabilities actively being exploited in the wild, we will aim to release an emergency patch within **72 hours** and coordinate with CERT/CC if necessary.

---

## Bug Bounty Scope

OWASP Sentinel is a bug bounty *platform* — we take irony seriously. The following scope applies to the Sentinel codebase itself:

### In Scope

- Authentication & authorisation bypass (JWT, RBAC, session management)
- Remote code execution (RCE) via report upload, template injection, Celery tasks
- SQL injection / NoSQL injection
- Server-side request forgery (SSRF) in scanner integrations
- Stored / Reflected / DOM cross-site scripting (XSS) with demonstrable impact
- Insecure direct object references (IDOR) affecting multiple users
- Sensitive data exposure (credentials, PII, vulnerability reports of other users)
- Business logic flaws (e.g., bypassing payment/reward gates, privilege escalation)
- Supply-chain issues in first-party code (not third-party dependencies)

### Out of Scope

- Vulnerabilities in third-party dependencies (report upstream; notify us if we should pin/patch)
- Self-XSS with no realistic attack path
- Rate limiting / brute-force issues without demonstrated account compromise risk
- Missing security headers without exploitable impact
- Denial-of-service requiring exceptional resources (>10 Gbps DDoS)
- Social engineering or physical attacks
- Issues already listed in known limitations or open GitHub issues
- Attacks against the reporter's own account only

---

## Security Best Practices for Deployers

When running Sentinel in production, ensure you:

1. **Rotate all default credentials** — change every value in `.env.example` before deployment.
2. **Keep services off the public internet** — Postgres, Redis, Meilisearch, and Prometheus should never be publicly accessible.
3. **Enable TLS everywhere** — Traefik handles Let's Encrypt automatically when `DOMAIN` and `ACME_EMAIL` are set.
4. **Apply principle of least privilege** — use separate DB credentials for Celery workers vs. the API.
5. **Review Celery task code** — arbitrary task execution can lead to RCE if not properly sandboxed.
6. **Subscribe to security advisories** — watch this repository for security release notifications.

---

## Acknowledgements

We gratefully recognise researchers who have reported valid vulnerabilities. Their contributions make Sentinel safer for everyone.

_No reports yet — be the first!_
