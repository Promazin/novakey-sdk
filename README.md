# 🗝️ NovaKey SDK

[![Stellar Protocol 21](https://img.shields.io/badge/Stellar-Protocol_21-black?style=flat&logo=stellar)](https://stellar.org)
[![Soroban](https://img.shields.io/badge/Smart_Contracts-Soroban-orange?style=flat)](https://soroban.stellar.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![NPM Version](https://img.shields.io/badge/npm-v1.0.0--alpha-green.svg)](https://npmjs.com/)

**NovaKey SDK** is a comprehensive, enterprise-grade developer toolkit for building passkey-native, seedless smart wallets on the Stellar network. 

Designed specifically for fintechs, NGOs, and Web3 builders in emerging markets, NovaKey leverages Soroban smart contracts and native `secp256r1` verification to turn any user's smartphone into a secure, non-custodial hardware wallet. By abstracting away seed phrases and XLM gas fees, NovaKey provides a Web2-style onboarding experience while maintaining strict Web3 security principles.

---

## 📑 Table of Contents
- [The Mission](#-the-mission)
- [Project Structure](#-project-structure)
- [Architecture & Technical Stack](#-architecture--technical-stack)
- [Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Environment Setup](#environment-setup)
- [Usage Guide](#-usage-guide)
  - [1. Initialization](#1-initialization)
  - [2. Wallet Creation](#2-wallet-creation)
  - [3. Sponsored Transactions](#3-sponsored-transactions)
  - [4. Account Recovery](#4-account-recovery)
- [Local Development & Testing](#-local-development--testing)
- [Roadmap (SCF Milestones)](#-roadmap-scf-milestones)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🌍 The Mission
In emerging markets, unbanked users seeking refuge in USD stablecoins face two major friction points:
1. **Seed Phrase Management:** 12-to-24 word passwords are counter-intuitive, intimidating, and easily lost.
2. **Gas Fees:** Requiring users to fund an account with a volatile native token (XLM) just to transact in stablecoins (USDC) halts user acquisition.

**NovaKey solves this.** By packaging complex cryptographic curves and gas-abstraction relayers into a few simple React hooks, developers can deploy consumer-facing DeFi apps that feel exactly like CashApp or M-Pesa.

---

## 📂 Project Structure

This repository is built as a **Turborepo Monorepo**, separating the smart contracts, the core TypeScript logic, frontend framework wrappers, and demo applications.

```text
novakey-workspace/
│
├── contracts/                  # Soroban Smart Contracts (Rust)
│   ├── factory/                # Deploys individual user Smart Wallets deterministically
│   ├── smart_wallet/           # Core Smart Contract Account logic (secp256r1 verification, nonces)
│   └── tests/                  # Rust integration tests for the contracts
│
├── packages/                   # NPM Packages
│   ├── novakey-core/           # Vanilla TypeScript SDK (WebAuthn generation, XDR building)
│   ├── novakey-react/          # React context and hooks for easy frontend integration
│   └── novakey-relayer-node/   # Backend Node.js utility for self-hosting a gas-sponsoring relayer
│
├── apps/                       # Demo and testing applications
│   ├── web/               # Next.js web application demonstrating wallet creation & transfer
│   └── mobile/            # React Native (Expo) app demonstrating native biometric prompts
│
├── .env.example                # Example environment variables
├── package.json                # Root package.json for Turborepo
└── README.md                   # This file
```

---

## 🏗️ Architecture & Technical Stack

NovaKey bridges client-side biometric hardware with on-chain Soroban execution via a three-tier architecture:

1. **Client (Device Enclave):** Utilizing the `WebAuthn` API, the user's device generates a `secp256r1` keypair. The private key remains locked in the device's Secure Enclave (FaceID/TouchID).
2. **The Relayer (Gas Abstraction):** The NovaKey SDK wraps the user's signed intent into an XDR payload and forwards it to a Relayer API. The Relayer bundles this with a fee-bump transaction, paying the XLM network fee on the user's behalf.
3. **Soroban Smart Contract:** The transaction hits the user's previously deployed Smart Wallet contract. The contract invokes its `__check_auth` function, utilizing Stellar Protocol 21's native `secp256r1` verification to authenticate the device's signature before moving funds.

---

## 🚀 Getting Started

### Prerequisites

To work with the full monorepo (including compiling smart contracts), you will need:
- **Node.js** v18+ and `pnpm` or `yarn` workspaces
- **Rust** target `wasm32-unknown-unknown`
- **Soroban CLI** (`cargo install --locked soroban-cli`)
- A Stellar RPC URL (e.g., from validation cloud or Stellar public testnet)

### Installation

If you are just building an app using the SDK, install the packages directly into your project:

```bash
npm install @novakey/core @novakey/react
```

### Environment Setup

Create a `.env` file at the root of your frontend application:

```env
NEXT_PUBLIC_STELLAR_NETWORK=testnet
NEXT_PUBLIC_RPC_URL=https://soroban-testnet.stellar.org
NEXT_PUBLIC_RELAYER_URL=https://relayer.yourdomain.com/api/v1/relay
NEXT_PUBLIC_FACTORY_CONTRACT_ID=C...YOUR_FACTORY_ADDRESS
```

---

## 📖 Usage Guide

### 1. Initialization
Wrap your React application in the `NovaKeyProvider` to establish connection with the network and your relayer.

```tsx
// _app.tsx or layout.tsx
import { NovaKeyProvider } from '@novakey/react';

export default function App({ Component, pageProps }) {
  return (
    <NovaKeyProvider 
      network={process.env.NEXT_PUBLIC_STELLAR_NETWORK}
      rpcUrl={process.env.NEXT_PUBLIC_RPC_URL}
      relayerUrl={process.env.NEXT_PUBLIC_RELAYER_URL}
    >
      <Component {...pageProps} />
    </NovaKeyProvider>
  );
}
```

### 2. Wallet Creation
Use the `createWallet` function to trigger the device's biometric prompt. This generates the WebAuthn credentials and deploys the Soroban smart contract via the Factory.

```tsx
import { useNovaKey } from '@novakey/react';

export function Onboarding() {
  const { createWallet, isCreating, address } = useNovaKey();

  const handleRegister = async () => {
    try {
      const newAddress = await createWallet({ 
        relyingPartyName: "My Fintech App",
        userName: "user@example.com" 
      });
      console.log("Deployed Smart Wallet:", newAddress);
    } catch (error) {
      console.error("Setup failed:", error);
    }
  };

  return (
    <div>
      <button onClick={handleRegister} disabled={isCreating}>
        {isCreating ? "Deploying On-Chain Vault..." : "Create Account with FaceID"}
      </button>
      {address && <p>Your Wallet: {address}</p>}
    </div>
  );
}
```

### 3. Sponsored Transactions
Send tokens (like USDC) without requiring the user to hold XLM. The SDK automatically requests a biometric signature and forwards it to the relayer.

```tsx
import { useTransaction } from '@novakey/react';

export function SendFunds() {
  const { sendSponsoredTx, isPending } = useTransaction();

  const handleSend = async () => {
    const receipt = await sendSponsoredTx({
      to: "G...RECEIVER_ADDRESS",
      amount: "50.00", 
      assetContractId: "C...USDC_CONTRACT_ADDRESS",
    });
    console.log("Transaction Hash:", receipt.txHash);
  };

  return (
    <button onClick={handleSend} disabled={isPending}>
      Send 50 USDC (Gasless)
    </button>
  );
}
```

### 4. Account Recovery
NovaKey supports social recovery and guardian configurations natively within the smart contract.

- **Set Guardian:** The wallet owner can designate a trusted recovery guardian (`set_guardian`).
- **Execute Recovery:** If all passkeys are lost, the guardian can authorize `recover_wallet` to replace the lost credentials with a new passkey.
- **Nonce Invalidation:** Recovery automatically advances the monotonic nonce by `+1`, invalidating any stale or intercepted signatures.

For full cryptographic and security specifications, see [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md).

---

## 🛠️ Local Development & Testing

To develop and test across the repository:

1. **Clone and install dependencies:**
   ```bash
   git clone https://github.com/your-org/novakey-sdk.git
   cd novakey-sdk
   ```

2. **Run TypeScript SDK Tests:**
   ```bash
   npm test
   ```

3. **Run Smart Contract Tests:**
   ```bash
   cd contracts
   cargo test
   ```

4. **Compile Smart Contracts to WebAssembly:**
   ```bash
   cd contracts
   make build
   # Outputs optimized .wasm binaries in target/wasm32-unknown-unknown/release
   ```

5. **Run Example Flow:**
   ```bash
   node examples/basic-wallet-flow.ts
   ```

---

## 🗺️ Roadmap 

- **Phase 1 (Completed):** Core Rust Smart Contract architecture, native `secp256r1` verification, deterministic factory deployment, guardian recovery, contract event system, and integration test suites.
- **Phase 2 (Completed):** TypeScript core SDK (`@novakey/core`) bridging WebAuthn assertions to Soroban authorization payloads, low-s signature normalization, deterministic address derivation, and unit tests.
- **Phase 3 (Current):** `@novakey/react` wrapper, complete open-source relayer node server, and Testnet beta launch.
- **Phase 4 (Target: Q2):** React Native (iOS/Android) native biometrics bridge, third-party security audits, and Stellar Mainnet deployment.

---

## 🤝 Contributing

We believe in public goods. If you want to help make Stellar the most accessible blockchain in the world, please contribute!
Read our [CONTRIBUTING.md](./CONTRIBUTING.md) for detailed guidelines on PR submissions, coding standards, and setting up the local Rust/Soroban testnet environment.

---

## 🛡️ Security Disclaimer

This SDK and the underlying Soroban contracts are currently in **Alpha**. They have **not** yet undergone a formal third-party security audit. Do not use this software in a production environment with mainnet assets until the official `v1.0.0` release. 

---

## 📄 License

NovaKey SDK is released under the [MIT License](LICENSE).
