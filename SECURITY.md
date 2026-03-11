# Security Policy

## Overview

The OWASP Sentinel team takes security seriously. We appreciate responsible disclosure of vulnerabilities and are committed to investigating and addressing all reported security issues promptly.

---

## Supported Versions

Only the following versions of OWASP Sentinel receive security updates:

| Version | Supported          | End of Support |
|---------|--------------------|----------------|
| 3.x     | ✅ Active support  | TBD            |
| 2.x     | ⚠️ Critical only   | 2025-06-30     |
| 1.x     | ❌ End of life      | 2024-12-31     |
| < 1.0   | ❌ End of life      | 2024-06-30     |

We strongly recommend all users upgrade to the latest **3.x** release.

---

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Public disclosure before a fix is available puts all users at risk. Instead, report vulnerabilities through one of the following channels:

### Option 1 — GitHub Private Security Advisory (Preferred)

1. Go to the repository's **Security** tab
2. Click **"Report a vulnerability"**
3. Fill out the advisory form with as much detail as possible
4. Submit — only maintainers and you will have access

### Option 2 — Email

Send a detailed report to: **security@owasp-sentinel.io**

Encrypt your report using our PGP key (fingerprint: `A1B2 C3D4 E5F6 7890 ABCD EF01 2345 6789 BCDE F012`).

---

## What to Include in Your Report

To help us triage and reproduce the vulnerability quickly, please provide:

- **Description**: A clear summary of the vulnerability and its impact
- **Affected component**: Which service, endpoint, or module is affected
- **Attack vector**: How the vulnerability can be triggered (unauthenticated / authenticated, network / local)
- **Steps to reproduce**: Detailed, numbered steps with commands or payloads
- **Proof of concept**: Code, screenshots, or HTTP request/response captures (if available)
- **Impact assessment**: What an attacker could achieve (data leakage, RCE, privilege escalation, etc.)
- **Suggested fix**: Your recommendation, if you have one
- **Your contact info**: For follow-up questions

---

## Responsible Disclosure Policy

We follow a coordinated vulnerability disclosure process:

1. **Report received** — You submit a vulnerability report privately
2. **Acknowledgement** — We confirm receipt within **48 hours**
3. **Triage** — We assess severity (CVSS score) within **5 business days**
4. **Fix development** — We develop and test a patch
5. **Release** — We release a patched version and publish a security advisory
6. **Disclosure** — You may publicly disclose after the patch is released or after **90 days**, whichever comes first

We ask that you:

- Give us reasonable time to fix the issue before public disclosure
- Do not access, modify, or exfiltrate data belonging to other users
- Do not perform denial-of-service attacks
- Do not use the vulnerability to attack our infrastructure or users
- Act in good faith throughout the disclosure process

We will:

- Acknowledge your report promptly
- Keep you informed of progress
- Credit you in the security advisory (unless you prefer anonymity)
- Not pursue legal action against researchers acting in good faith

---

## Response Timeline

| Stage                         | Target SLA         |
|-------------------------------|--------------------|
| Acknowledgement               | 48 hours           |
| Initial severity assessment   | 5 business days    |
| Critical severity patch       | 7 days             |
| High severity patch           | 14 days            |
| Medium severity patch         | 30 days            |
| Low severity patch            | 90 days            |
| Public advisory               | At patch release   |

For **critical** vulnerabilities (CVSS ≥ 9.0) that are being actively exploited, we aim to release a hotfix within 24–48 hours.

---

## Severity Classification

We use the [CVSS v3.1](https://www.first.org/cvss/v3-1/) scoring system:

| CVSS Score | Severity | Response SLA |
|------------|----------|--------------|
| 9.0–10.0   | Critical | 7 days       |
| 7.0–8.9    | High     | 14 days      |
| 4.0–6.9    | Medium   | 30 days      |
| 0.1–3.9    | Low      | 90 days      |

---

## Scope

### In Scope

The following are in scope for vulnerability reports:

- All services in the `docker-compose.yml` (backend, frontend, worker, etc.)
- Authentication and authorisation logic
- API endpoints (REST and WebSocket)
- Scan engine components and tool integrations
- Report generation and storage
- User data handling and privacy

### Out of Scope

- Third-party dependencies (report those directly to the dependency maintainer)
- Social engineering attacks
- Physical security
- Issues in versions that have reached end of life
- Rate limiting / brute force without demonstrated impact
- Missing security headers without a concrete exploit path
- Self-XSS requiring victim to paste attacker-controlled code
- Open redirects without demonstrated impact beyond phishing

---

## Bug Bounty

At this time, OWASP Sentinel does **not** operate a formal bug bounty programme. However, we deeply value the security research community and will:

- Credit all reporters in our Hall of Fame (with permission)
- Provide a personalised letter of acknowledgement for significant findings
- Offer swag (stickers, t-shirts) for critical and high severity findings

---

## Hall of Fame

We are grateful to the following security researchers who have responsibly disclosed vulnerabilities to us:

| Researcher | Finding | Year |
|------------|---------|------|
| *Your name here* | — | — |

If you have reported a vulnerability and would like to be listed, please let us know in your report.

---

## Security Best Practices for Operators

If you are deploying OWASP Sentinel in your own environment, we recommend:

1. **Rotate all default secrets** — Replace every value in `.env.example` before going to production
2. **Use TLS everywhere** — Configure Traefik with a valid TLS certificate (Let's Encrypt or your PKI)
3. **Restrict network access** — Place internal services (Postgres, Redis, MinIO) on a private network; never expose them directly to the internet
4. **Enable authentication** on Grafana, Flower, MinIO console, and Traefik dashboard in production
5. **Keep images up to date** — Pull the latest base images regularly and rebuild
6. **Enable Postgres audit logging** — Use `pgaudit` for production compliance
7. **Limit scan permissions** — Run scan tools with the minimum required OS capabilities
8. **Back up your data** — Automate backups for Postgres and MinIO buckets
9. **Monitor for anomalies** — Use the bundled Grafana dashboards and configure alerting
10. **Review your firewall rules** — Ensure only necessary ports are exposed per environment

---

## Contact

- **Security disclosures**: security@owasp-sentinel.io
- **General security questions**: Raise a GitHub Discussion tagged `security`
- **OWASP project page**: https://owasp.org/www-project-sentinel
