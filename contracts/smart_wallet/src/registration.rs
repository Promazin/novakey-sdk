use soroban_sdk::{Bytes, BytesN, Env};

use crate::{
    error::SmartWalletError,
    storage,
    types::Credential,
};

/// Maximum number of passkeys a single wallet may register.
pub const MAX_CREDENTIALS: u32 = 10;

/// Maximum byte length of a credential label.
pub const MAX_LABEL_BYTES: usize = 64;

/// Register a new passkey credential, persisting it to storage.
///
/// Validates that:
/// - The wallet is initialised.
/// - The label fits within `MAX_LABEL_BYTES`.
/// - No credential with this ID already exists.
/// - The total credential count stays ≤ `MAX_CREDENTIALS`.
///
/// Bumps the TTL of the new entry so it survives at least 30 days.
pub fn register_credential(
    env: &Env,
    credential_id: &BytesN<16>,
    public_key: &BytesN<65>,
    label: &Bytes,
) -> Result<(), SmartWalletError> {
    if label.len() as usize > MAX_LABEL_BYTES {
        return Err(SmartWalletError::LabelTooLong);
    }

    if storage::load_credential(env, credential_id).is_some() {
        return Err(SmartWalletError::CredentialAlreadyExists);
    }

    let mut list = storage::load_credential_ids(env);
    if list.ids.len() >= MAX_CREDENTIALS {
        return Err(SmartWalletError::MaxCredentialsReached);
    }

    let credential = Credential {
        public_key: public_key.clone(),
        label: label.clone(),
    };

    storage::save_credential(env, credential_id, &credential);
    storage::bump_credential_ttl(env, credential_id);

    list.ids.push_back(credential_id.clone());
    storage::save_credential_ids(env, &list);

    Ok(())
}

/// Deregister a credential.
///
/// The last credential cannot be removed to prevent self-lockout.
pub fn deregister_credential(
    env: &Env,
    credential_id: &BytesN<16>,
) -> Result<(), SmartWalletError> {
    if storage::load_credential(env, credential_id).is_none() {
        return Err(SmartWalletError::CredentialNotFound);
    }

    let mut list = storage::load_credential_ids(env);

    // Prevent permanent self-lockout.
    if list.ids.len() <= 1 {
        return Err(SmartWalletError::CredentialNotFound);
    }

    storage::remove_credential(env, credential_id);

    let new_ids = list
        .ids
        .iter()
        .filter(|id| *id != *credential_id)
        .collect();
    list.ids = new_ids;
    storage::save_credential_ids(env, &list);

    Ok(())
}
