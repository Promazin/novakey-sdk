use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env, Vec};

use crate::{
    error::SmartWalletError,
    storage,
    types::{Credential, SignaturePayload},
};

/// Maximum number of passkeys a single wallet may register.
const MAX_CREDENTIALS: u32 = 10;

/// Maximum byte length of a credential label.
const MAX_LABEL_BYTES: usize = 64;

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

        if label.len() as usize > MAX_LABEL_BYTES {
            return Err(SmartWalletError::LabelTooLong);
        }

        storage::set_initialized(&env);
        storage::set_owner(&env, &owner);
        storage::set_nonce(&env, 0);

        let credential = Credential { public_key, label };
        storage::save_credential(&env, &credential_id, &credential);

        let mut list = storage::load_credential_ids(&env);
        list.ids.push_back(credential_id);
        storage::save_credential_ids(&env, &list);

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

        if label.len() as usize > MAX_LABEL_BYTES {
            return Err(SmartWalletError::LabelTooLong);
        }

        if storage::load_credential(&env, &credential_id).is_some() {
            return Err(SmartWalletError::CredentialAlreadyExists);
        }

        let mut list = storage::load_credential_ids(&env);
        if list.ids.len() >= MAX_CREDENTIALS {
            return Err(SmartWalletError::MaxCredentialsReached);
        }

        let credential = Credential { public_key, label };
        storage::save_credential(&env, &credential_id, &credential);
        list.ids.push_back(credential_id);
        storage::save_credential_ids(&env, &list);

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

        if storage::load_credential(&env, &credential_id).is_none() {
            return Err(SmartWalletError::CredentialNotFound);
        }

        // Guard: never remove the last key or the wallet becomes permanently locked.
        let mut list = storage::load_credential_ids(&env);
        if list.ids.len() <= 1 {
            // Removing the last credential would lock the wallet forever.
            // Return an error to prevent accidental self-lockout.
            return Err(SmartWalletError::CredentialNotFound);
        }

        storage::remove_credential(&env, &credential_id);

        // Rebuild the ID list without this entry.
        let new_ids: Vec<BytesN<16>> = list
            .ids
            .iter()
            .filter(|id| *id != credential_id)
            .collect();
        list.ids = new_ids;
        storage::save_credential_ids(&env, &list);

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

    fn require_initialized(env: &Env) -> Result<(), SmartWalletError> {
        if !storage::is_initialized(env) {
            return Err(SmartWalletError::NotInitialized);
        }
        Ok(())
    }
}
