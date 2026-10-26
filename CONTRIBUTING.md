# Contributing to NovaKey SDK

Thank you for your interest in contributing to **NovaKey SDK**! NovaKey is designed to bring non-custodial, passkey-native smart wallets to Stellar Protocol 21 and Soroban.

---

## 🛠️ Development Setup

### Prerequisites

1. **Rust:**
   - Install Rust via [rustup](https://rustup.rs/):
     ```bash
     curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
     ```
   - Add the `wasm32-unknown-unknown` compilation target:
     ```bash
     rustup target add wasm32-unknown-unknown
     ```
2. **Node.js & pnpm:**
   - Node.js v20+
   - Corepack or npm for pnpm / package management.
3. **Soroban CLI (optional for local deployment):**
   ```bash
   cargo install --locked soroban-cli
   ```

---

## 🧪 Running Tests

### Smart Contracts (Rust)

Run unit and integration tests:
```bash
cd contracts
cargo test
```

Build release WebAssembly contracts:
```bash
make build
```

### TypeScript SDK

Run SDK tests from repository root:
```bash
npm test
```

Or within the package:
```bash
cd packages/novakey-core
node --test tests/*.test.ts
```

---

## 📐 Project Structure

```text
novakey-sdk/
├── .github/workflows/     # CI/CD workflows
├── contracts/             # Soroban Smart Contracts (Rust)
│   ├── factory/           # Deterministic smart wallet factory
│   ├── smart_wallet/      # Core smart wallet account (secp256r1 auth, nonces, recovery)
│   └── tests/             # Contract integration and unit tests
└── packages/              # Monorepo packages
    └── novakey-core/      # Core TypeScript WebAuthn and XDR tooling
```

---

## 📋 Git Commit Guidelines

We adhere to the [Conventional Commits](https://www.conventionalcommits.org/) specification:

- `feat:` New features or public APIs
- `fix:` Bug fixes
- `test:` Adding or updating tests
- `docs:` Documentation improvements
- `ci:` CI/CD and workflow changes
- `refactor:` Code refactoring without changing functionality
- `chore:` Build scripts, dependency updates, and maintenance

---

## 🛡️ Security Vulnerabilities

If you identify a security vulnerability, please do NOT open a public GitHub issue. Instead, report it privately to the maintainers at security@novakey.dev.
