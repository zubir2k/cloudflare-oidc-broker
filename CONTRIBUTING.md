# Contributing to Cloudflare OIDC Broker

Thank you for your interest in contributing! This project is built by the community, for the community. Whether you're fixing a typo, adding a new upstream provider, or proposing a major architectural change, your contributions are welcome.

## 🧭 How to Contribute

### Reporting Bugs

Before opening an issue, please:

1. Check the [existing issues](https://github.com/zubir2k/cloudflare-oidc-broker/issues) to avoid duplicates.
2. Ensure you're running the **latest version** of the project.
3. Use the **Bug Report** issue template.

A good bug report includes:

- A clear, descriptive title.
- Steps to reproduce the issue.
- Expected vs. actual behavior.
- Your environment (Node version, Wrangler version, browser).
- Relevant logs (redact any secrets!).

### Suggesting Features

We love new ideas! Before opening a feature request:

1. Check if it's already been discussed in [Discussions](https://github.com/zubir2k/cloudflare-oidc-broker/discussions).
2. Consider whether the feature aligns with the project's goals (see [Project Goals](#project-goals)).
3. Use the **Feature Request** issue template.

### Submitting Pull Requests

1. **Fork** the repository.
2. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/my-awesome-feature
   ```
3. **Make your changes** following the guidelines below.
4. **Test your changes** (see [Testing](#testing)).
5. **Commit** with a clear, conventional message:
   ```bash
   git commit -m "feat: add Apple Sign In provider"
   git commit -m "fix: handle missing email_verified claim"
   git commit -m "docs: clarify PKCE enforcement"
   ```
6. **Push** and open a Pull Request against `main`.
7. **Fill out the PR template** completely.

## 🛠️ Development Setup

### Prerequisites

- Node.js 20+
- npm 10+
- A Cloudflare account (free tier works)
- Wrangler CLI (`npm install -g wrangler`)

### Local Setup

```bash
git clone https://github.com/zubir2k/cloudflare-oidc-broker.git
cd cloudflare-oidc-broker
npm install
cp wrangler.toml.example wrangler.toml
# Fill in wrangler.toml with your test credentials
npm run dev
```

The broker will be available at `http://localhost:8787`.

## 📐 Code Style

- **Language**: TypeScript (strict mode).
- **Runtime**: Cloudflare Workers (V8 isolates) — no Node.js APIs.
- **Formatting**: Prettier (config included).
- **Linting**: ESLint (config included).

Before submitting, run:

```bash
npm run lint
npm run type-check
npm run format
```

## 🧪 Testing

Testing is **critical** for authentication software. A bug here can mean account takeovers.

### What to Test

- ✅ New providers must include tests for the happy path and edge cases (unverified emails, missing claims).
- ✅ Any change to `/authorize`, `/token`, or `/callback` must be tested.
- ✅ PKCE enforcement must be verified.
- ✅ SQL queries must be parameterized (no string concatenation).

### Running Tests

```bash
npm test
```

If you're adding a new provider, please add a corresponding test file under `tests/providers/`.

## 🆕 Adding a New Upstream Provider

We welcome new providers! To add one:

1. Create a new file in `src/providers/` (e.g., `discord.ts`).
2. Implement the `OAuthProvider` interface from `src/types.ts`.
3. Handle email verification explicitly (see existing providers for examples).
4. Register the provider in `src/providers/index.ts`.
5. Add the necessary secrets to `wrangler.toml.example`.
6. Update the README to list the new provider.
7. Add tests.

**Important**: Providers must enforce `email_verified` where the upstream API supports it. If the upstream API does not provide this claim, document the limitation clearly.

## 🎯 Project Goals

This project aims to be:

- **Secure by default**: OAuth 2.1 compliant, no deprecated flows.
- **Lightweight**: Fits within Cloudflare's free tier for personal use.
- **Self-hostable**: No external dependencies beyond Cloudflare.
- **Provider-agnostic**: Supports any OAuth 2.0 / OIDC upstream.
- **Simple**: Minimal configuration, sensible defaults.

We generally **reject** contributions that:

- Introduce unnecessary dependencies.
- Add features that only apply to a single downstream app.
- Compromise security for convenience.
- Require persistent infrastructure beyond Workers + D1 + KV.

## 💬 Communication

- **Questions?** Open a [Discussion](https://github.com/zubir2k/cloudflare-oidc-broker/discussions).
- **Bugs?** Open an [Issue](https://github.com/zubir2k/cloudflare-oidc-broker/issues).
- **Security vulnerabilities?** See [SECURITY.md](SECURITY.md) — **do not** open a public issue.

## 📜 License

By contributing, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).

## 🙏 Recognition

All contributors are recognized in our [Contributors](https://github.com/zubir2k/cloudflare-oidc-broker/graphs/contributors) page. Significant contributions may also be highlighted in release notes.

---

*Thank you for helping make Cloudflare OIDC Broker better for everyone!*