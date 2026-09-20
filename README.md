# 🔐 Cloudflare OIDC Broker

A serverless, edge-deployed OpenID Connect (OIDC) broker built on **Cloudflare Workers**. 
Federate social logins (Google, GitHub, Microsoft, Apple) and issue standard OIDC tokens 
to your self-hosted apps — with zero infrastructure to manage.

> **Disclaimer**: This is an independent, community-driven project and is not affiliated with, endorsed by, or sponsored by Cloudflare, Inc. Cloudflare is a trademark of Cloudflare, Inc.

## 🎯 Why This Exists

- **Self-branded identity**: Your apps authenticate against `id.yourdomain.com`, not Google directly.
- **Per-app user mapping**: Map Google accounts to different local usernames per application.
- **Access control**: Allowlist exactly which Google accounts can log in, and to which apps.
- **Zero infrastructure**: Runs on Cloudflare Workers + D1 + KV, fitting entirely within the free tier.
- **OAuth 2.1 compliant**: PKCE S256 enforced, authorization code flow only, no implicit flow.

## 🏗️ Architecture

```text
Browser ──> /authorize ──> Google OAuth ──> /callback ──> Downstream App
                │                              │
           KV (session)                  D1 (user mapping)
```

The broker never stores upstream provider tokens. It exchanges them immediately for a broker-signed RS256 `id_token` issued under your own issuer URL.

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
| `GET|POST <ADMIN_ROUTE_PATH>/*`   | Admin console (Zero Trust protected) |

## 🚀 Setup

### 1. Prerequisites

- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/) installed and authenticated
- A Cloudflare account (free tier is sufficient)
- OAuth 2.0 credentials from your chosen upstream providers (Google, GitHub, etc.)

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
npx wrangler secret put BROKER_PUBLIC_KEY_JWK
```

### 7. Deploy

```bash
npx wrangler deploy
```

### 8. Custom Domain

In the Cloudflare dashboard, add a custom domain route for your Worker (e.g., `id.yourdomain.com`).

## 🛡️ Admin Console

The admin console is protected by **Cloudflare Zero Trust Access**. Set `CF_ACCESS_TEAM_NAME` and `CF_ACCESS_AUD` in `wrangler.toml`, then configure an Access application pointing at `<your-domain><ADMIN_ROUTE_PATH>`.

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
├── index.ts              # Main router and all OIDC endpoint handlers
├── types.ts              # TypeScript interfaces (Env, DB models, OIDC schemas)
├── providers/            # Upstream provider implementations (Google, GitHub, etc.)
├── utils/
│   ├── origin.ts         # Issuer and canonical URL resolution
│   ├── pkce.ts           # RFC 7636 PKCE challenge verification
│   ├── jwt.ts            # RS256 JWT minting via jose
│   ├── access.ts         # Cloudflare Zero Trust JWT verification
│   └── oidc.ts           # Discovery document and JWKS response
└── views/
    └── adminConsole.ts   # Admin console HTML renderer
schema.sql                # Fresh install schema (D1)
wrangler.toml.example     # Configuration template
```

## ✅ Tested With

- Home Assistant (`homeassistant/generic_oauth2`)
- Synology DSM (OIDC SSO)
- WordPress
- Nextcloud

## 🤝 Contributing & Security

- Found a bug or have a feature request? Please [open an issue](https://github.com/zubir2k/cloudflare-oidc-broker/issues).
- Want to contribute? Please read our [Contributing Guidelines](CONTRIBUTING.md).
- Found a security vulnerability? Please review our [Security Policy](SECURITY.md).

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---
*Made with 🔐 by [Zubir Jamal](https://zubir.tech)*