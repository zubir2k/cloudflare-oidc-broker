# Security Policy

Security is foundational to this project. As an OpenID Connect broker, this software participates directly in authentication, authorization, identity processing, and token issuance.

This document explains the project's security model, privacy boundaries, supported versions, deployment responsibilities, and vulnerability-reporting process.

---

## Supported Versions

Only the latest published version on the main branch receives security updates.

| Version | Supported |
|---|---|
| Latest | ✅ Security fixes |
| Earlier than latest | ❌ Not supported |

Before reporting a vulnerability, confirm that the issue is reproducible against the latest version.

---

## Security Model

### Trust boundary

The broker sits between approved upstream identity providers and registered downstream applications.

```text
Approved upstream provider
           │
           │ Authenticates the user
           ▼
┌─────────────────────────┐
│       OIDC Broker       │
│                         │
│ Validate identity       │
│ Apply authorization     │
│ Derive local identity   │
│ Issue broker tokens     │
└─────────────────────────┘
           │
           │ Broker-issued claims
           ▼
Registered downstream application
```

Upstream providers authenticate identities. The broker validates the upstream response, applies local authorization policy, derives a broker-controlled identity, and issues its own tokens. Downstream applications trust the broker rather than integrating directly with every upstream provider.

### Trusted components

A deployment operator explicitly chooses to trust:

- The deployed broker code
- The broker operator
- The Cloudflare account and deployment configuration
- Configured upstream identity providers
- Registered downstream clients and redirect URIs
- Broker signing keys and provider secrets
- Administrative authentication and authorization controls

### Untrusted input

The broker treats the following as untrusted until validated:

- Browser requests
- OIDC and OAuth authorization parameters
- Redirect URIs
- Downstream client credentials
- Upstream callback parameters
- Upstream tokens and claims
- User-selected provider values
- Administrative API requests

### Provider allowlisting

The broker must communicate only with providers that are present in the local provider registry and explicitly enabled by the deployment operator.

Arbitrary issuer URLs supplied by users or downstream clients must not become trusted providers dynamically.

A modular provider architecture does not mean that every OIDC provider is automatically trusted.

---

## Privacy and PII Handling

### Transient processing

The broker necessarily processes selected upstream identity attributes during authentication in order to validate identity, apply authorization policy, and derive a local mapping.

The reference implementation is designed so that:

- Raw upstream PII is not intended to be persisted in Cloudflare D1
- Raw upstream PII is not intended to be persisted in Cloudflare KV
- Upstream tokens are not forwarded to downstream applications
- Persistent mappings use derived or hashed identity references
- Downstream applications receive broker-issued identities and configured local claims
- Upstream tokens are discarded after the required validation and identity-processing steps

This reduces persistent exposure. It does not remove the need to trust the broker operator and the deployed code.

### Broker operator trust

A malicious or compromised broker deployment could be modified to log, transmit, or persist upstream identity attributes before they are discarded or transformed.

Open-source availability allows inspection of the published source code, but it does not independently prove that a public broker deployment is running the same code.

Users and downstream application owners must therefore trust the operator of the broker instance they use.

### Platform logging

Deployers should review Cloudflare logging, observability, traces, exception reporting, and debugging settings before handling real identities.

Application code should not log:

- Upstream access tokens
- Upstream ID tokens
- Authorization codes
- Client secrets
- Private signing keys
- Raw identity claims
- NRIC or other national identity numbers
- Email addresses or phone numbers unless explicitly required and appropriately protected

Debug logging should not be enabled in deployments handling real identities unless its data exposure has been reviewed and accepted.

### Hashing and pseudonymisation

Hashing an identifier does not automatically make it anonymous.

A deterministic hash may remain personal or pseudonymous data if the value can be linked, guessed, correlated, or reproduced using other information.

Identity derivation should include appropriate provider and client context so that the same upstream identity does not produce a universal identifier across all downstream applications.

### Account linking

Accounts from different upstream providers must not be linked merely because they return the same email address or display name.

For example:

```text
Google:          admin@example.com
GitHub:          admin@example.com
Another issuer:  admin@example.com
```

These values alone do not prove that all three accounts belong to the same person.

Cross-provider linking should require an explicit and controlled mapping decision by the broker operator.

### Identity assurance

Different providers may apply different authentication, account recovery, verification, and identity-proofing processes.

An authenticated account from one provider should not automatically be treated as equivalent in assurance to an authenticated identity from another provider.

Authorization policies should reflect the assurance required for each downstream application.

---

## Threat Model and Limitations

The reference implementation is designed to reduce common OAuth and OIDC implementation risks, but it cannot protect against every threat.

### Within the project's security scope

- OIDC protocol implementation, including `/authorize`, `/token`, `/userinfo`, and `/callback`
- JWT signing and verification using RS256
- PKCE enforcement
- Upstream provider integrations implemented in this repository
- Provider registry and enablement logic
- Redirect URI validation
- State, nonce, authorization-code, and session handling
- Admin console authentication and authorization
- D1 interactions, including parameterization and access control
- KV-backed ephemeral state
- Token revocation and logout flows
- Cryptographic key handling by this project
- Unintended persistence or disclosure of identity attributes by the reference code

### Outside the project's control

- Vulnerabilities within an upstream provider
- Cloudflare platform vulnerabilities
- Compromise of the operator's Cloudflare account
- Malicious operators or deployments intentionally modified from the published code
- Downstream application vulnerabilities
- Misconfigured downstream clients
- Weak or compromised upstream user credentials
- Availability attacks requiring platform-level mitigation
- Vulnerabilities in third-party dependencies that must be remediated upstream
- Regulatory or legal compliance of a particular deployment

### No automatic security guarantee

Authentication succeeding does not prove that an implementation or deployment is secure.

The following should not be inferred solely from this project's features or test results:

- Complete security
- Production readiness
- OpenID certification
- Regulatory compliance
- High availability
- Correct configuration
- Safety of custom forks or modifications
- Trustworthiness of a particular broker operator

---

## Security Controls

The reference implementation includes controls such as:

- Authorization Code Flow
- PKCE S256 enforcement
- Exact registered redirect URI validation
- Upstream state and nonce validation
- Upstream token signature and claim validation where applicable
- Short-lived, single-use broker authorization codes
- RS256-signed broker ID tokens
- Client-specific subject identifiers
- Provider allowlisting
- Mixed client-authentication method rejection
- Restricted cross-origin behavior
- `Cache-Control: no-store` on sensitive responses
- Secure and HTTP-only session cookies where applicable
- Security response headers
- Parameterized D1 queries
- User and client suspension controls

These controls depend on correct deployment, configuration, secret management, and ongoing maintenance.

---

## OpenID Connect Conformance

The broker has been tested using the OpenID Foundation Conformance Suite for the Basic OP profile.

[View the public Basic OP test plan](https://www.certification.openid.net/plan-detail.html?plan=wCGJeSQHOEVT2)

Conformance testing provides evidence about the protocol behaviors exercised by the selected test plan.

It does not by itself establish:

- OpenID certification
- Complete security assurance
- Production readiness
- Availability or resilience
- Regulatory compliance
- Correct deployment configuration
- Safety of custom modifications

The public test result should be read together with its warnings, review items, skipped modules, test configuration, and the OpenID Foundation's own disclaimer.

---

## Security Best Practices for Deployers

Deployers should:

- Store provider secrets and the broker private signing key as Cloudflare Secrets
- Never place secrets or private keys in `wrangler.toml` or version control
- Enable only required upstream providers
- Protect administrative routes using Cloudflare Access or another appropriately secured control
- Restrict and monitor administrative API tokens
- Review Cloudflare logs and observability settings for PII exposure
- Avoid logging upstream tokens and raw identity claims
- Use dedicated provider credentials for each broker deployment
- Apply rate limiting to `/authorize`, `/callback`, `/token`, and administrative routes
- Back up D1 configuration securely
- Protect and rotate signing keys and provider secrets
- Review all redirect URIs before approving clients
- Use exact redirect URI matching
- Keep token and session lifetimes as short as operationally practical
- Monitor D1 and KV activity for unexpected usage
- Keep dependencies and Wrangler updated
- Review provider-specific assumptions before enabling a new module
- Obtain an independent security review before using the broker for sensitive or production workloads

### Signing-key rotation

If the broker private key is compromised:

1. Generate a new signing key pair.
2. Update the broker secret.
3. Publish the corresponding public key through JWKS.
4. Redeploy the broker.
5. Review whether active sessions or issued tokens must be revoked.
6. Investigate the source and scope of the compromise.

A mature deployment should support overlapping public keys during planned rotation so previously issued tokens can be validated until they expire.

---

## Vulnerability Reporting

Please do not disclose a suspected vulnerability in a public GitHub issue.

### Option 1: GitHub Security Advisories

This is the preferred reporting channel.

1. Open the repository's **Security** tab.
2. Select **Report a vulnerability**.
3. Provide the information requested below.

This keeps the report private while remediation and coordinated disclosure are discussed.

### Option 2: Email

Send a report to **hello@zubirjamal.com** with the subject:

```text
[SECURITY] cloudflare-oidc-broker: <brief description>
```

PGP-encrypted email is welcome. Contact the maintainer first to exchange keys if required.

### What to include

A useful report should include:

- **Description:** Clear explanation of the vulnerability
- **Impact:** What an attacker could achieve
- **Steps to reproduce:** Minimal reproducible proof of concept
- **Affected versions:** Release or commit affected
- **Environment:** Relevant deployment and configuration details
- **Suggested fix:** Optional remediation proposal

Do not include real user credentials, raw production PII, active private keys, or live tokens unless specifically requested through a secure channel.

---

## Response Targets

| Milestone | Target |
|---|---|
| Acknowledgment | 48 hours |
| Initial triage | 5 business days |
| Critical fix development | 14 days |
| Moderate fix development | 30 days |
| Coordinated disclosure | Up to 90 days from report |

These are targets rather than guarantees. Timing may vary based on complexity, reproducibility, dependencies, and maintainer availability.

---

## Responsible Disclosure

Security researchers are asked to:

- Avoid exploiting a vulnerability beyond what is necessary to demonstrate it
- Avoid accessing, modifying, or deleting other users' data
- Avoid collecting or retaining real identity attributes
- Avoid testing against production deployments without explicit authorization
- Avoid service disruption or denial-of-service activity
- Keep vulnerability details private until a reasonable remediation period has passed

For researchers following this policy, the project intends to:

- Treat reports respectfully and in good faith
- Acknowledge receipt within the stated target
- Coordinate remediation and disclosure
- Credit the reporter when requested and appropriate
- Avoid legal action for good-faith research conducted within this policy

---

## Contact

For security architecture questions, vulnerability reports, and coordinated disclosure discussions, use GitHub Security Advisories or **hello@zubirjamal.com**.

_Last updated: October 2026_
