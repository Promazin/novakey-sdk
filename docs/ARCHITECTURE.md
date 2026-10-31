# NovaKey Architecture & Technical Specification

NovaKey SDK enables seedless, non-custodial smart contract accounts on Stellar using WebAuthn / passkey hardware credentials and Soroban Protocol 21 native `secp256r1` cryptographic verification.

---

## 🏛️ System Overview

The system architecture consists of three interconnected layers:

```text
┌─────────────────────────┐
│     User Device         │
│  (Secure Enclave/FIDO2) │  Biometric authentication produces secp256r1 signature
└───────────┬─────────────┘
            │
            ▼ (AuthPayload via HTTP)
┌─────────────────────────┐
│  Gas-Sponsoring Relayer │  Wraps user payload into Soroban invocation + Fee Bump
└───────────┬─────────────┘
            │
            ▼ (XDR on Stellar Ledger)
┌─────────────────────────┐
│  Soroban Smart Wallet   │  Native __check_auth validates signature & consumes nonce
└─────────────────────────┘
```

---

## 🔑 Cryptographic Pipeline

### 1. Key Generation & Extraction
The user's device enclave generates an ECDSA keypair on the NIST P-256 (`secp256r1`) curve:
- Private key: Never leaves the device hardware (FaceID / TouchID / TPM).
- Public key: Exported via WebAuthn as either a 91-byte ASN.1 DER `SubjectPublicKeyInfo` (`SPKI`), a CBOR-encoded `COSE_Key` EC2 map, or a 65-byte uncompressed SEC1 point (`0x04 || X(32) || Y(32)`). `@novakey/core` normalizes all formats into the canonical 65-byte uncompressed representation and validates non-zero coordinates on both client and contract.
- Credential ID: 16-byte identifier exported during WebAuthn registration (or SHA-256 truncated to 16 bytes for longer authenticator IDs).

### 2. Transaction Signing & Normalization
When authorizing a transaction:
1. The client retrieves the wallet's current monotonic nonce (`nonce: u64`).
2. The client receives the 32-byte Soroban authorization payload hash (`operation_hash: BytesN<32>`).
3. The device enclave signs the 40-byte serialized payload (`nonce_le || operation_hash`).
4. WebAuthn returns an ASN.1 DER signature.
5. `@novakey/core` normalizes the signature into a 64-byte compact representation `(r || s)`:
   - If $s > \frac{n}{2}$, $s = n - s$ (enforcing low-$s$ to prevent ECDSA signature malleability).

### 3. On-Chain Verification (`__check_auth`)
Soroban routes authorization through the contract's custom account entry point:
```rust
fn __check_auth(
    env: Env,
    signature_payload: Hash<32>,
    signatures: AuthPayload,
    auth_contexts: Vec<Context>,
) -> Result<(), SmartWalletError>
```

Verification protocol:
1. **Operation Integrity:** Ensures `signature_payload` from the Soroban host equals `signatures.signed.operation_hash`.
2. **Replay Protection:** Ensures `signatures.signed.nonce` equals contract's current nonce; increments nonce atomically.
3. **secp256r1 Verification:** Calls Stellar Protocol 21 native host function:
   ```rust
   env.crypto().secp256r1_verify(public_key, payload_hash, signature)
   ```
4. **State TTL Extension:** Bumps storage entry TTL so the account remains active indefinitely under active use.

---

## 🏭 Deterministic Wallet Deployment

The `FactoryContract` deploys individual user wallets deterministically using Soroban's address derivation API:

$$\text{salt} = \text{SHA-256}(\text{credential\_id})$$
$$\text{wallet\_address} = \text{deployer}(\text{factory\_address}, \text{salt})$$

Benefits:
- **Zero-lookup client resolution:** The client SDK predicts the wallet address before submitting the deployment transaction.
- **Counterfactual account funding:** Applications can transfer stablecoins to the predicted address before the user ever deploys the contract code.

---

## 🛡️ Account Recovery & Security Controls

### 1. Guardian Social Recovery
If a user loses all registered passkeys, NovaKey provides non-custodial social recovery:
1. The wallet owner registers a trusted `guardian: Address` via `set_guardian`.
2. The guardian can trigger `recover_wallet(new_credential_id, new_public_key, new_label)`:
   - Requires `guardian.require_auth()`.
   - Clears all existing registered credentials.
   - Installs the new passkey credential as the sole active key.
   - Advances the wallet nonce by $+1$ to invalidate any pending unexecuted signatures.
   - Automatically lifts any active emergency lock.
   - Emits a `wallet_recovered` contract event.

### 2. Emergency Freeze / Account Lock
To protect against stolen physical devices or suspected credential compromise:
- **Locking:** Either the wallet `owner` or the recovery `guardian` can invoke `lock_wallet(caller)`.
- **Enforcement:** While locked, `__check_auth` immediately reverts with `SmartWalletError::WalletLocked (13)`, rejecting all outgoing transaction attempts.
- **Unlocking:** Either the `owner` or `guardian` can invoke `unlock_wallet(caller)`, or completing guardian recovery automatically resets the lock.

---

## ⚡ Gas-Sponsoring Relayer Architecture

The `@novakey/relayer-node` service provides gas abstraction and fee-bump sponsorship:
- **Mempool Nonce Tracking:** Prevents transaction replay attacks before on-chain confirmation.
- **Idempotency Protection:** Clients attach an `idempotencyKey` / `Idempotency-Key` header so network retries return identical receipts without failing or double-sponsoring fees.
- **Pre-flight Simulation:** `POST /api/v1/simulate` validates signature structures and fee limits without broadcasting.
- **Nonce Discovery:** `GET /api/v1/nonce/:walletAddress` allows clients to discover the next available monotonic nonce.
- **Transaction History:** `GET /api/v1/history/:walletAddress` returns timestamped audit records for a wallet.

---

## 📡 Event Architecture

Both `SmartWalletContract` and `FactoryContract` emit structured contract events:

| Contract | Event Topic | Event Data | Purpose |
| :--- | :--- | :--- | :--- |
| `SmartWallet` | `("credential_registered", credential_id)` | `label` | Passkey added |
| `SmartWallet` | `("credential_removed", credential_id)` | `()` | Passkey removed |
| `SmartWallet` | `("credential_label_updated", credential_id)` | `new_label` | Passkey device label updated |
| `SmartWallet` | `("auth_success", credential_id)` | `(nonce, operation_hash)` | Transaction authorized |
| `SmartWallet` | `("guardian_set", guardian)` | `()` | Recovery guardian set |
| `SmartWallet` | `("guardian_removed", ())` | `()` | Recovery guardian removed |
| `SmartWallet` | `("wallet_recovered", guardian)` | `new_credential_id` | Wallet recovered |
| `SmartWallet` | `("wallet_locked", caller)` | `()` | Emergency freeze activated |
| `SmartWallet` | `("wallet_unlocked", caller)` | `()` | Emergency freeze lifted |
| `SmartWallet` | `("ownership_transferred", old_owner)` | `new_owner` | Wallet owner rotated |
| `SmartWallet` | `("wallet_upgraded", owner)` | `new_wasm_hash` | Wallet WASM upgraded |
| `Factory` | `("wallet_deployed", owner)` | `(wallet_address, credential_id)` | Wallet deployed |
| `Factory` | `("wasm_updated", admin)` | `new_wasm_hash` | Smart wallet WASM upgraded |
| `Factory` | `("admin_transferred", old_admin)` | `new_admin` | Factory admin rotated |
