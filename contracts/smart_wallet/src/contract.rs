use soroban_sdk::{auth::Context, contract, contractimpl, Address, Bytes, BytesN, Env, Vec};

use crate::{
    auth::{check_auth, AuthPayload},
    error::SmartWalletError,
    registration,
    storage,
    types::{Credential, SignaturePayload},
};

#[contract]
pub struct SmartWalletContract;

#[contractimpl]
impl SmartWalletContract {
    // ── Initialisation ────────────────────────────────────────────────────────

    /// Initialise the wallet with the owner address and the first passkey.
    ///
    /// Must be called exactly once, immediately after deployment (typically by
    /// the Factory contract). Subsequent calls return `AlreadyInitialized`.
    ///
    /// # Arguments
    /// * `owner`         – The Stellar address that owns this wallet.
    /// * `credential_id` – 16-byte CBOR credential ID from the WebAuthn response.
    /// * `public_key`    – 65-byte uncompressed secp256r1 public key.
    /// * `label`         – Human-readable device label (e.g. "iPhone 15 FaceID").
    pub fn initialize(
        env: Env,
        owner: Address,
        credential_id: BytesN<16>,
        public_key: BytesN<65>,
        label: Bytes,
    ) -> Result<(), SmartWalletError> {
        if storage::is_initialized(&env) {
            return Err(SmartWalletError::AlreadyInitialized);
        }

        storage::set_initialized(&env);
        storage::set_owner(&env, &owner);
        storage::set_nonce(&env, 0);

        registration::register_credential(&env, &credential_id, &public_key, &label)?;

        storage::bump_instance_ttl(&env);
        Ok(())
    }

    // ── Credential management ─────────────────────────────────────────────────

    /// Add a new passkey credential to this wallet.
    ///
    /// Requires the owner to authorise (via `require_auth`).
    pub fn add_credential(
        env: Env,
        credential_id: BytesN<16>,
        public_key: BytesN<65>,
        label: Bytes,
    ) -> Result<(), SmartWalletError> {
        Self::require_initialized(&env)?;
        let owner = storage::get_owner(&env).ok_or(SmartWalletError::NotInitialized)?;
        owner.require_auth();

        registration::register_credential(&env, &credential_id, &public_key, &label)?;
        storage::bump_instance_ttl(&env);
        Ok(())
    }

    /// Remove a registered passkey credential.
    ///
    /// Requires the owner to authorise.
    pub fn remove_credential(
        env: Env,
        credential_id: BytesN<16>,
    ) -> Result<(), SmartWalletError> {
        Self::require_initialized(&env)?;
        let owner = storage::get_owner(&env).ok_or(SmartWalletError::NotInitialized)?;
        owner.require_auth();

        registration::deregister_credential(&env, &credential_id)?;
        storage::bump_instance_ttl(&env);
        Ok(())
    }

    // ── Read helpers ──────────────────────────────────────────────────────────

    /// Return all registered credential IDs.
    pub fn list_credentials(env: Env) -> Result<Vec<BytesN<16>>, SmartWalletError> {
        Self::require_initialized(&env)?;
        Ok(storage::load_credential_ids(&env).ids)
    }

    /// Return the credential for a given ID.
    pub fn get_credential(
        env: Env,
        credential_id: BytesN<16>,
    ) -> Result<Credential, SmartWalletError> {
        Self::require_initialized(&env)?;
        storage::load_credential(&env, &credential_id)
            .ok_or(SmartWalletError::CredentialNotFound)
    }

    /// Return the current nonce.
    pub fn get_nonce(env: Env) -> Result<u64, SmartWalletError> {
        Self::require_initialized(&env)?;
        Ok(storage::get_nonce(&env))
    }

    /// Return the wallet owner address.
    pub fn owner(env: Env) -> Result<Address, SmartWalletError> {
        Self::require_initialized(&env)?;
        storage::get_owner(&env).ok_or(SmartWalletError::NotInitialized)
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    pub(crate) fn require_initialized(env: &Env) -> Result<(), SmartWalletError> {
        if !storage::is_initialized(env) {
            return Err(SmartWalletError::NotInitialized);
        }
        Ok(())
    }
}

// ── Custom account interface ──────────────────────────────────────────────────
//
// Implementing `CustomAccountInterface` tells the Soroban host that this
// contract IS the account for auth purposes. When any contract calls
// `require_auth` against this wallet's address, the host routes the check
// here instead of requiring a classic ed25519 signature.

use soroban_sdk::auth::CustomAccountInterface;

#[contractimpl]
impl CustomAccountInterface for SmartWalletContract {
    type Signature = AuthPayload;
    type Error = SmartWalletError;

    /// Called by the Soroban host to authenticate a transaction.
    ///
    /// Returns `Ok(())` to approve, or a [`SmartWalletError`] to reject.
    fn __check_auth(
        env: Env,
        signature_payload: AuthPayload,
        auth_context: Vec<Context>,
    ) -> Result<(), SmartWalletError> {
        Self::require_initialized(&env)?;
        check_auth(&env, &signature_payload, &auth_context)
    }
}

// Silence the unused-import lint on SignaturePayload — it is part of the public
// API re-exported from lib.rs and used by AuthPayload.
#[allow(dead_code)]
fn _assert_types(_: SignaturePayload) {}
