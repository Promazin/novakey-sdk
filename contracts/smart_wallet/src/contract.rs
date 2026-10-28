use soroban_sdk::{auth::Context, contract, contractimpl, Address, Bytes, BytesN, Env, Vec};

use crate::{
    auth::{check_auth, AuthPayload},
    error::SmartWalletError,
    events,
    recovery,
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

    /// Update the human-readable label of an existing passkey credential.
    ///
    /// Requires the owner to authorise.
    pub fn update_credential_label(
        env: Env,
        credential_id: BytesN<16>,
        new_label: Bytes,
    ) -> Result<(), SmartWalletError> {
        Self::require_initialized(&env)?;
        let owner = storage::get_owner(&env).ok_or(SmartWalletError::NotInitialized)?;
        owner.require_auth();

        registration::update_credential_label(&env, &credential_id, &new_label)?;
        storage::bump_instance_ttl(&env);
        Ok(())
    }

    // ── Ownership & lifecycle management ──────────────────────────────────────

    /// Transfer ownership of this smart wallet to a new Stellar address.
    ///
    /// Requires the current owner to authorise.
    pub fn transfer_ownership(
        env: Env,
        new_owner: Address,
    ) -> Result<(), SmartWalletError> {
        Self::require_initialized(&env)?;
        let old_owner = storage::get_owner(&env).ok_or(SmartWalletError::NotInitialized)?;
        old_owner.require_auth();

        storage::set_owner(&env, &new_owner);
        storage::bump_instance_ttl(&env);
        events::ownership_transferred(&env, &old_owner, &new_owner);
        Ok(())
    }

    /// Upgrade the smart wallet contract executable to a new WASM hash.
    ///
    /// Requires the owner to authorise.
    pub fn upgrade(
        env: Env,
        new_wasm_hash: BytesN<32>,
    ) -> Result<(), SmartWalletError> {
        Self::require_initialized(&env)?;
        let owner = storage::get_owner(&env).ok_or(SmartWalletError::NotInitialized)?;
        owner.require_auth();

        env.deployer().update_current_contract_wasm(new_wasm_hash.clone());
        storage::bump_instance_ttl(&env);
        events::wallet_upgraded(&env, &owner, &new_wasm_hash);
        Ok(())
    }

    // ── Recovery management ───────────────────────────────────────────────────

    /// Configure a recovery guardian address. Requires owner authorization.
    pub fn set_guardian(env: Env, guardian: Address) -> Result<(), SmartWalletError> {
        Self::require_initialized(&env)?;
        let owner = storage::get_owner(&env).ok_or(SmartWalletError::NotInitialized)?;
        owner.require_auth();

        storage::set_guardian(&env, &guardian);
        events::guardian_set(&env, &guardian);
        storage::bump_instance_ttl(&env);
        Ok(())
    }

    /// Retrieve the recovery guardian address if configured.
    pub fn get_guardian(env: Env) -> Result<Option<Address>, SmartWalletError> {
        Self::require_initialized(&env)?;
        Ok(storage::get_guardian(&env))
    }

    /// Remove the recovery guardian. Requires owner authorization.
    pub fn remove_guardian(env: Env) -> Result<(), SmartWalletError> {
        Self::require_initialized(&env)?;
        let owner = storage::get_owner(&env).ok_or(SmartWalletError::NotInitialized)?;
        owner.require_auth();

        storage::remove_guardian(&env);
        events::guardian_removed(&env);
        storage::bump_instance_ttl(&env);
        Ok(())
    }

    /// Recover account by replacing all credentials with a new passkey.
    /// Requires guardian authorization.
    pub fn recover_wallet(
        env: Env,
        new_credential_id: BytesN<16>,
        new_public_key: BytesN<65>,
        new_label: Bytes,
    ) -> Result<(), SmartWalletError> {
        Self::require_initialized(&env)?;
        recovery::recover_wallet(&env, &new_credential_id, &new_public_key, &new_label)
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
use soroban_sdk::crypto::Hash;

#[contractimpl]
impl CustomAccountInterface for SmartWalletContract {
    type Signature = AuthPayload;
    type Error = SmartWalletError;

    /// Called by the Soroban host to authenticate a transaction.
    ///
    /// Returns `Ok(())` to approve, or a [`SmartWalletError`] to reject.
    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        signatures: AuthPayload,
        auth_context: Vec<Context>,
    ) -> Result<(), SmartWalletError> {
        Self::require_initialized(&env)?;
        check_auth(&env, &signature_payload, &signatures, &auth_context)
    }
}

// Silence the unused-import lint on SignaturePayload — it is part of the public
// API re-exported from lib.rs and used by AuthPayload.
#[allow(dead_code)]
fn _assert_types(_: SignaturePayload) {}
