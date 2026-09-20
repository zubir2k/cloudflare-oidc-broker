# Security Policy

Security is the foundation of this project. As an OpenID Connect broker handling authentication flows and user identity, we take vulnerabilities extremely seriously.

## Supported Versions

We actively maintain the **latest release** on the `main` branch. Only the latest published version receives security updates.

| Version     | Supported          |
|-------------|--------------------|
| latest      | ✅ Security fixes  |
| < latest    | ❌ Not supported   |

Please ensure you are running the most recent release before reporting a vulnerability.

## Scope

### ✅ In Scope

- Core OIDC protocol implementation (`/authorize`, `/token`, `/userinfo`, `/callback`)
- JWT signing and verification (RS256)
- PKCE enforcement (RFC 7636)
- Upstream provider integrations (Google, GitHub, Microsoft, Apple)
- Admin console authentication and authorization
- Session management (KV-backed)
- D1 database interactions (SQL injection, access control)
- Token revocation and logout flows
- Cryptographic key handling

### ❌ Out of Scope

- Vulnerabilities in upstream providers (Google, GitHub, etc.)
- Cloudflare platform-level issues (report via [Cloudflare Security](https://www.cloudflare.com/security/))
- Denial-of-service attacks that require Cloudflare-tier mitigation
- Issues in third-party dependencies (report upstream first)
- Missing security headers that Cloudflare's edge already handles
- Theoretical attacks without a working proof of concept

## Reporting a Vulnerability

### Option 1: GitHub Security Advisories (Preferred)

1. Go to the [Security tab](https://github.com/zubir2k/cloudflare-oidc-broker/security) of this repository.
2. Click **"Report a vulnerability"**.
3. Fill out the form with as much detail as possible.

This keeps the report **private** until we coordinate disclosure.

### Option 2: Email

Send a detailed report to **hello@zubirjamal.com** with the subject line:

```
[SECURITY] cloudflare-oidc-broker: <brief description>
```

PGP-encrypted emails are welcome. Contact us first to exchange keys if needed.

## What to Include

A good report helps us triage quickly. Please include:

- **Description**: A clear explanation of the vulnerability.
- **Impact**: What an attacker could achieve (e.g., account takeover, token forgery).
- **Steps to Reproduce**: Minimal, reproducible proof of concept.
- **Affected Versions**: Which release(s) or commit(s) are affected.
- **Suggested Fix** (optional): If you have ideas, we'd love to hear them.

## Response Timeline

| Milestone                  | Target Time   |
|----------------------------|---------------|
| Acknowledgment             | 48 hours      |
| Initial triage             | 5 business days |
| Fix development            | 14 days (critical) / 30 days (moderate) |
| Coordinated disclosure     | 90 days from report |

## Responsible Disclosure

We kindly ask that you:

- **Do not** exploit the vulnerability beyond what is necessary to demonstrate it.
- **Do not** access, modify, or delete other users' data.
- **Do not** disclose the vulnerability publicly until we have had a reasonable time to address it.
- **Do not** perform attacks against production deployments (including the author's).

In return, we commit to:

- Treating your report with urgency and respect.
- Not taking legal action against researchers who follow this policy.
- Crediting you in the security advisory (unless you prefer to remain anonymous).
- Publishing a detailed post-mortem after the fix is released.

## Security Best Practices for Deployers

If you are running this broker, please ensure you:

1. ✅ Store all secrets (`UPSTREAM_*_CLIENT_SECRET`, `BROKER_PRIVATE_KEY_JWK`) as **Cloudflare Secrets**, never in `wrangler.toml`.
2. ✅ Protect the admin console with **Cloudflare Zero Trust Access**.
3. ✅ Enforce HTTPS on your custom domain (Cloudflare does this by default).
4. ✅ Rotate your RS256 signing key periodically.
5. ✅ Monitor your D1 and KV usage for anomalies.
6. ✅ Keep your `wrangler` CLI and dependencies up to date.

## Security Highlights

This project implements several security controls by design:

- **OAuth 2.1 compliance**: Only the Authorization Code flow with PKCE (S256) is supported. The deprecated Implicit flow is not available.
- **Strict upstream email verification**: GitHub accounts must have a verified primary email; other providers' `email_verified` claims are strictly enforced.
- **Cryptographically secure secrets**: Client secrets are generated using `crypto.getRandomValues()` with a minimum length of 32 characters.
- **No implicit trust**: The broker never trusts email addresses without upstream verification.
- **Parameterized SQL**: All D1 queries use bound parameters to prevent SQL injection.
- **Short-lived sessions**: Authorization codes and broker sessions expire within 5 minutes.

## Contact

For security inquiries that are not vulnerability reports (e.g., architecture questions, audit requests), please reach out via the same channels above.

---

*Last updated: September 2026*