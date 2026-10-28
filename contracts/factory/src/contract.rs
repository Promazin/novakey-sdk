use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env, Symbol, Val, Vec};

use crate::{error::FactoryError, events, storage};

#[contract]
pub struct FactoryContract;

#[contractimpl]
impl FactoryContract {
    // ── Initialisation ────────────────────────────────────────────────────────

    /// Initialise the factory with the SmartWallet WASM hash and an admin address.
    ///
    /// Must be called once right after deploying the factory. The `wasm_hash`
    /// is the SHA-256 digest of the compiled `smart_wallet.wasm` binary that
    /// has been uploaded to the ledger with `soroban contract install`.
    pub fn initialize(
        env: Env,
        admin: Address,
        wasm_hash: BytesN<32>,
    ) -> Result<(), FactoryError> {
        if storage::is_initialized(&env) {
            return Err(FactoryError::AlreadyInitialized);
        }

        Self::validate_wasm_hash(&env, &wasm_hash)?;

        storage::set_initialized(&env);
        storage::set_admin(&env, &admin);
        storage::set_wasm_hash(&env, &wasm_hash);
        storage::bump_instance_ttl(&env);

        Ok(())
    }

    // ── Wallet deployment ─────────────────────────────────────────────────────

    /// Deploy a new SmartWallet for a user and initialise it with their passkey.
    ///
    /// The wallet address is deterministic:
    /// ```text
    /// salt    = SHA-256(credential_id)
    /// address = deployer(factory_address, salt)
    /// ```
    /// The SDK can therefore predict the wallet address client-side before
    /// the transaction is confirmed.
    ///
    /// # Arguments
    /// * `owner`         – The Stellar address that will own the wallet.
    /// * `credential_id` – 16-byte CBOR credential ID from WebAuthn registration.
    /// * `public_key`    – 65-byte uncompressed secp256r1 public key from the device.
    /// * `label`         – Human-readable device label (e.g. "Pixel 8 Fingerprint").
    ///
    /// # Returns
    /// The deployed wallet's contract address.
    pub fn deploy_wallet(
        env: Env,
        owner: Address,
        credential_id: BytesN<16>,
        public_key: BytesN<65>,
        label: Bytes,
    ) -> Result<Address, FactoryError> {
        Self::require_initialized(&env)?;

        // Prevent duplicate deployments for the same credential.
        if storage::load_wallet_address(&env, &credential_id).is_some() {
            return Err(FactoryError::WalletAlreadyExists);
        }

        let wasm_hash = storage::get_wasm_hash(&env)
            .ok_or(FactoryError::NotInitialized)?;

        // Derive a deterministic salt from the credential ID.
        let salt = Self::derive_salt(&env, &credential_id);

        // Deploy the SmartWallet contract instance.
        let wallet_address = env
            .deployer()
            .with_current_contract(salt)
            .deploy(wasm_hash);

        // Initialise the freshly deployed wallet.
        // We call its `initialize` function via a cross-contract call.
        let init_args: Vec<Val> = soroban_sdk::vec![
            &env,
            owner.to_val(),
            credential_id.to_val(),
            public_key.to_val(),
            label.to_val(),
        ];

        env.invoke_contract::<()>(
            &wallet_address,
            &Symbol::new(&env, "initialize"),
            init_args,
        );

        // Record the deployment so we can look it up and prevent duplicates.
        storage::save_wallet_address(&env, &credential_id, &wallet_address);
        storage::bump_wallet_ttl(&env, &credential_id);
        storage::bump_instance_ttl(&env);

        events::wallet_deployed(&env, &owner, &wallet_address, &credential_id);

        Ok(wallet_address)
    }

    // ── Admin operations ──────────────────────────────────────────────────────

    /// Update the SmartWallet WASM hash used for future deployments.
    ///
    /// Does not affect already-deployed wallets — those must be upgraded
    /// individually by their owners.
    pub fn set_wasm_hash(
        env: Env,
        new_wasm_hash: BytesN<32>,
    ) -> Result<(), FactoryError> {
        Self::require_initialized(&env)?;
        Self::validate_wasm_hash(&env, &new_wasm_hash)?;

        let admin = storage::get_admin(&env).ok_or(FactoryError::NotInitialized)?;
        admin.require_auth();

        storage::set_wasm_hash(&env, &new_wasm_hash);
        storage::bump_instance_ttl(&env);

        events::wasm_hash_updated(&env, &admin, &new_wasm_hash);

        Ok(())
    }

    // ── Read helpers ──────────────────────────────────────────────────────────

    /// Return the current factory administrator address.
    pub fn get_admin(env: Env) -> Result<Address, FactoryError> {
        Self::require_initialized(&env)?;
        storage::get_admin(&env).ok_or(FactoryError::NotInitialized)
    }

    /// Return the currently configured SmartWallet WASM hash.
    pub fn get_wasm_hash(env: Env) -> Result<BytesN<32>, FactoryError> {
        Self::require_initialized(&env)?;
        storage::get_wasm_hash(&env).ok_or(FactoryError::NotInitialized)
    }

    /// Look up the wallet address for a given credential ID.
    ///
    /// Returns `None` if no wallet has been deployed for this credential.
    pub fn get_wallet(env: Env, credential_id: BytesN<16>) -> Option<Address> {
        storage::load_wallet_address(&env, &credential_id)
    }

    /// Predict the wallet address for a credential ID without deploying.
    ///
    /// Useful for the SDK to show the user their address at registration time.
    pub fn predict_wallet_address(env: Env, credential_id: BytesN<16>) -> Address {
        let salt = Self::derive_salt(&env, &credential_id);
        env.deployer()
            .with_current_contract(salt)
            .deployed_address()
    }

    /// Returns the factory contract version.
    pub fn version(_env: Env) -> u32 {
        1
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn require_initialized(env: &Env) -> Result<(), FactoryError> {
        if !storage::is_initialized(env) {
            return Err(FactoryError::NotInitialized);
        }
        Ok(())
    }

    /// Ensure the WASM hash is not all zeros.
    fn validate_wasm_hash(env: &Env, hash: &BytesN<32>) -> Result<(), FactoryError> {
        let zero = BytesN::from_array(env, &[0u8; 32]);
        if *hash == zero {
            return Err(FactoryError::InvalidWasmHash);
        }
        Ok(())
    }

    /// Derive a 32-byte salt from a 16-byte credential ID.
    ///
    /// `salt = SHA-256(credential_id_bytes)`
    fn derive_salt(env: &Env, credential_id: &BytesN<16>) -> BytesN<32> {
        let cred_bytes: Bytes = credential_id.clone().into();
        env.crypto().sha256(&cred_bytes).into()
    }
}
