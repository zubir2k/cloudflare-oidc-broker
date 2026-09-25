# 🔐 Cloudflare OIDC Broker

[![GitHub Repo stars](https://img.shields.io/github/stars/zubir2k/cloudflare-oidc-broker?style=social)](https://github.com/zubir2k/cloudflare-oidc-broker/stargazers)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-orange)](https://workers.cloudflare.com/)
[![OIDC Basic OP Compliant](https://img.shields.io/badge/OIDC-Basic%20OP%20Compliant-success)](https://www.certification.openid.net/plan-detail.html?plan=wCGJeSQHOEVT2)
[![Buy](https://img.shields.io/badge/Belanja-Coffee-yellow.svg)](https://zubirco.de/buymecoffee)

A secure, serverless, edge-deployed OpenID Connect (OIDC) broker built on **Cloudflare Workers**. 
Federate social logins (Google, GitHub, Microsoft, Apple) and issue standard OIDC tokens 
to your self-hosted apps — with zero infrastructure to manage and enterprise-grade security.

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/zubir2k/cloudflare-oidc-broker)

**Note:** After deploying, complete the [Setup Guide](#-setup) to configure your database, KV namespace, and secrets before the broker is functional.

> **Disclaimer**: This is an independent, community-driven project and is not affiliated with, endorsed by, or sponsored by Cloudflare, Inc. Cloudflare is a trademark of Cloudflare, Inc.

## 🎯 Why This Exists

- **Self-branded identity**: Your apps authenticate against `id.yourdomain.com`, not Google directly.
- **Per-app user mapping**: Map provider accounts to different local usernames per application.
- **Access control**: Allowlist exactly which accounts can log in, and to which apps.
- **Zero infrastructure**: Runs on Cloudflare Workers + D1 + KV, fitting entirely within the free tier.
- **OAuth 2.1 aligned**: PKCE S256 enforced for *all* clients, authorization code flow only, no implicit flow.
- **Cryptographic upstream validation**: Validates upstream ID tokens (checking `iss`, `aud`, `nonce`, `exp`) instead of blindly trusting `/userinfo` endpoints.

## 🏗️ Architecture

```text
Browser ──> /authorize ──> Upstream Provider ──> /callback ──> Downstream App
                │                 (Validates ID Token)     │
           KV (session)                       D1 (user mapping & sub hashing)
```

The broker never stores upstream provider tokens. It exchanges them immediately, cryptographically validates the upstream ID token, generates a deterministic hashed `sub` claim, and mints a broker-signed RS256 `id_token` issued under your own issuer URL.

## 🔄 How It Works

1. **Downstream Request:** A user attempts to log in to a downstream app (e.g., Home Assistant). The app redirects the user to the Broker's `/authorize` endpoint.
2. **Upstream Authentication:** The broker generates a secure session and redirects the user to the configured upstream provider (e.g., Google).
3. **Callback & Validation:** Upon successful upstream login, the provider redirects back to the broker's `/callback`. The broker cryptographically validates the upstream ID token and checks the user against the `user_mappings` database.
4. **Token Issuance:** If authorized, the broker generates a deterministic `sub`, mints a signed downstream ID token, and redirects the user back to the downstream app with a secure authorization code.

## 🆚 How This Compares to Cloudflare Access

This broker is **not** a replacement for Cloudflare Zero Trust (Access). Instead, it is a specialized **Federated Identity Broker** designed to solve specific edge cases that generic Access policies cannot handle:

- **Granular Per-App Mapping:** Unlike Access domain-wide policies, this broker uses a local database (`user_mappings`) to allow or deny specific users on a *per-application* basis (e.g., allow User A in Home Assistant, but deny them in Nextcloud).
- **Subject (`sub`) Isolation:** Cloudflare Access issues a global User UUID. This broker generates a deterministic, SHA-256 hashed `sub` scoped to each downstream client, preventing cross-application user correlation and enhancing privacy.
- **Identity Normalization:** It seamlessly aggregates multiple upstream providers (Google, Microsoft, GitHub) and normalizes their claims into a consistent format expected by downstream apps, regardless of the original provider's schema.
- **Cost Efficiency:** It runs entirely on Cloudflare Workers, D1, and KV, avoiding the per-seat licensing costs associated with Cloudflare Zero Trust paid plans.

*Note: This broker can be deployed alongside Cloudflare Access, using Access to protect the broker's own administrative endpoints or as one of the upstream identity providers.*

## 🧰 Stack

| Resource        | Cloudflare Product | Purpose                              |
|-----------------|--------------------|--------------------------------------|
| HTTP routing    | Workers            | OIDC endpoints                       |
| Client registry | D1                 | Registered apps and allowed redirect URIs |
| User directory  | D1                 | Provider email → local username mapping |
| Session cache   | KV                 | Ephemeral auth codes and tokens (TTL) |
| Admin console   | Workers + Zero Trust | Protected management UI             |

## 🔌 Endpoints

| Endpoint                          | Description                        |
|-----------------------------------|------------------------------------|
| `GET /.well-known/openid-configuration` | OIDC discovery document       |
| `GET /.well-known/jwks.json`      | Public key set (RS256)             |
| `GET /authorize`                  | Start authorization (redirect to provider) |
| `GET /callback`                   | Provider OAuth callback              |
| `POST /token`                     | Token endpoint (exchange code for id_token) |
| `GET /userinfo`                   | Userinfo endpoint                  |
| `POST /revoke`                    | Token revocation (RFC 7009)        |
| `GET /logout`                     | RP-initiated logout                |
| `GET, POST /admin/*`              | Admin console (Zero Trust protected, path configurable) |

## 🚀 Setup

### 1. Prerequisites

- OAuth 2.0 credentials from your chosen upstream providers (Google, GitHub, etc.)
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/) installed and authenticated
- A Cloudflare account (free tier is sufficient)

### 2. Provider OAuth Credentials

1. Go to your provider's developer console (e.g., [Google Cloud Console](https://console.cloud.google.com/))
2. Create an OAuth 2.0 Client ID (Web application)
3. Add `https://id.yourdomain.com/callback` as an authorized redirect URI
4. Note the **Client ID** and **Client Secret**

### 3. Cloudflare Resources

```bash
# Create D1 database
npx wrangler d1 create oidc-broker-db

# Create KV namespace
npx wrangler kv namespace create SESSIONS_KV

# Apply schema
npx wrangler d1 execute oidc-broker-db --remote --file=schema.sql
```

### 4. Configuration

Copy the example configuration and fill in the IDs from the previous step.

```bash
cp wrangler.toml.example wrangler.toml
```

### 5. Generate RS256 Key Pair

```bash
node -e "
const { webcrypto } = require('crypto');
(async () => {
  const { privateKey, publicKey } = await webcrypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' },
    true, ['sign', 'verify']
  );
  const priv = await webcrypto.subtle.exportKey('jwk', privateKey);
  const pub  = await webcrypto.subtle.exportKey('jwk', publicKey);
  pub.kid = crypto.randomUUID();
  priv.kid = pub.kid;
  console.log('PRIVATE:', JSON.stringify(priv));
  console.log('PUBLIC: ', JSON.stringify(pub));
})();
"
```

### 6. Set Secrets

```bash
npx wrangler secret put UPSTREAM_GOOGLE_CLIENT_SECRET
npx wrangler secret put UPSTREAM_GITHUB_CLIENT_SECRET
npx wrangler secret put BROKER_PRIVATE_KEY_JWK
npx wrangler secret put ADMIN_API_TOKEN  # (Optional but recommended) Defense-in-depth for admin routes
```

### 7. Deploy

```bash
npx wrangler deploy
```

### 8. Custom Domain

In the Cloudflare dashboard, add a custom domain route for your Worker (e.g., `id.yourdomain.com`).

## 🛡️ Admin Console

The admin console is protected by **Cloudflare Zero Trust Access**. Set `CF_ACCESS_TEAM_NAME` and `CF_ACCESS_AUD` in `wrangler.toml`, then configure an Access application pointing at `<your-domain><ADMIN_ROUTE_PATH>`.

> **Defense-in-Depth:** For added security, you can set the `ADMIN_API_TOKEN` secret. The Worker will then require *either* a valid Cloudflare Access session *or* a valid `Authorization: Bearer <token>` header, protecting against Zero Trust misconfigurations.

The console lets you:
- Register and manage downstream client applications
- Map provider accounts to local usernames (globally or per-app)
- Suspend users or clients instantly via the kill switch

## 🗺️ User Mappings

A mapping of `client_id = *` acts as a global fallback — the user can log in to any registered app.
A mapping scoped to a specific `client_id` takes precedence over the global one, allowing different usernames per application.

| email | client_id | username | effect |
|-------|-----------|----------|--------|
| `user@gmail.com` | `*` | `zubir` | logs in to all apps as `zubir` |
| `user@gmail.com` | `my-nas` | `admin` | logs in to `my-nas` as `admin`, other apps as `zubir` |

## 📂 Project Structure

```text
src/
├── index.ts              # Main router and OIDC endpoint handlers
├── types.ts              # Core TypeScript interfaces (Env, DB models, OIDC schemas)
├── providers/            # Upstream provider implementations
│   ├── types.ts          # Shared UpstreamProvider interface and user schemas
│   ├── registry.ts       # Centralized provider registration and routing
│   └── [google, microsoft, github, apple].ts
|                         # Individual provider logic & JWKS validation
├── utils/
│   ├── origin.ts         # Issuer and canonical URL resolution (forces HTTPS)
│   ├── pkce.ts           # RFC 7636 PKCE challenge verification
│   ├── jwt.ts            # RS256 JWT minting via jose
│   ├── access.ts         # Cloudflare Zero Trust JWT verification
│   ├── oidc.ts           # Discovery document and JWKS response
│   ├── clientAuth.ts     # Secure client credential parsing (rejects mixed auth)
│   └── subHash.ts        # Deterministic SHA-256 sub claim isolation
└── views/
    ├── adminConsole.ts   # Admin console HTML renderer
    ├── formPost.ts       # OIDC Form Post response mode HTML renderer
    └── errorPage.ts      # Context-aware Access Denied page (popup/main window)
```

## 🛡️ Security & Operational Best Practices

This broker is designed with a "Zero Trust" approach to identity brokering. Production deployments benefit from these built-in and recommended practices:

- **Strict Transport Security**: Enforces global `Strict-Transport-Security`, `X-Content-Type-Options`, and `Referrer-Policy` headers on all responses.
- **Cache Prevention**: Applies `Cache-Control: no-store` to `/token` and `/userinfo` endpoints per RFC 6749.
- **Locked-Down CORS**: Removed wide-open `Access-Control-Allow-Origin: *` from backend-to-backend token exchanges to prevent cross-origin abuse.
- **Mixed Auth Rejection**: Strictly enforces RFC 6749 §2.3 by rejecting clients that attempt to use both Basic Auth and body credentials simultaneously.
- **Adaptive Error Handling**: Features a context-aware "Access Denied" page that gracefully handles popup and main-window flows, bypassing non-compliant downstream clients (like Synology DSM and Home Assistant) that fail to process standard OAuth error redirects.
- **Rate Limiting (Recommended)**: Configure a Cloudflare WAF Rate Limiting rule for `/token` and `/authorize` (e.g., 10 requests per 10 seconds per IP) to prevent brute-force attacks.
- **Database Backups (Recommended)**: Regularly export your D1 database (`npx wrangler d1 export oidc-broker-db --output=backup.sql`) to ensure you can recover from accidental schema changes or data loss.
- **Key Rotation (Recommended)**: If your `BROKER_PRIVATE_KEY_JWK` is ever compromised, generate a new key pair, update the secret, and redeploy. Note that previously issued tokens will remain valid until their 1-hour expiration.

## ✅ Tested With

- Home Assistant ([cavefire/hass-openid](https://github.com/cavefire/hass-openid))
- Synology DSM (OIDC SSO)
- WordPress
- Proxmox VE

## ✅ OpenID Connect Conformance

This broker has been tested against the official **OpenID Foundation Conformance Suite** and passes all tests for the **Basic OP** profile. 
- **Test Results:** [View Public Test Logs](https://www.certification.openid.net/plan-detail.html?plan=wCGJeSQHOEVT2)

## 🤝 Contributing & Security

- Found a bug or have a feature request? Please [open an issue](https://github.com/zubir2k/cloudflare-oidc-broker/issues).
- Want to contribute? Please read our [Contributing Guidelines](CONTRIBUTING.md).
- Found a security vulnerability? Please review our [Security Policy](SECURITY.md).

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---
*Made with 🔐 by [Zubir Jamal](https://zubir.tech)*