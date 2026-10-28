use soroban_sdk::{Bytes, BytesN, Env};

use crate::{
    error::SmartWalletError,
    events,
    storage,
    types::Credential,
};

/// Maximum number of passkeys a single wallet may register.
pub const MAX_CREDENTIALS: u32 = 10;

/// Maximum byte length of a credential label.
pub const MAX_LABEL_BYTES: usize = 64;

/// Uncompressed SEC1 point prefix byte.
pub const UNCOMPRESSED_POINT_PREFIX: u8 = 0x04;

/// Validate that a 65-byte secp256r1 public key uses the uncompressed `0x04` prefix
/// and contains non-zero coordinate material.
pub fn validate_public_key(public_key: &BytesN<65>) -> Result<(), SmartWalletError> {
    if public_key.get(0) != Some(UNCOMPRESSED_POINT_PREFIX) {
        return Err(SmartWalletError::InvalidPublicKey);
    }

    let mut has_nonzero_coord = false;
    for i in 1..65 {
        if public_key.get(i).unwrap_or(0) != 0 {
            has_nonzero_coord = true;
            break;
        }
    }

    if !has_nonzero_coord {
        return Err(SmartWalletError::InvalidPublicKey);
    }

    Ok(())
}

/// Register a new passkey credential, persisting it to storage.
///
/// Validates that:
/// - The wallet is initialised.
/// - The public key is a valid uncompressed point (`0x04` prefix, non-zero coordinates).
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
    validate_public_key(public_key)?;

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

    events::credential_registered(env, credential_id, label);

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
        return Err(SmartWalletError::CannotRemoveLastCredential);
    }

    storage::remove_credential(env, credential_id);

    let mut new_ids = soroban_sdk::Vec::new(env);
    for id in list.ids.iter() {
        if id != *credential_id {
            new_ids.push_back(id);
        }
    }
    list.ids = new_ids;
    storage::save_credential_ids(env, &list);

    events::credential_removed(env, credential_id);

    Ok(())
}

/// Update the human-readable device label for an existing credential.
pub fn update_credential_label(
    env: &Env,
    credential_id: &BytesN<16>,
    new_label: &Bytes,
) -> Result<(), SmartWalletError> {
    if new_label.len() as usize > MAX_LABEL_BYTES {
        return Err(SmartWalletError::LabelTooLong);
    }

    let mut credential = storage::load_credential(env, credential_id)
        .ok_or(SmartWalletError::CredentialNotFound)?;

    credential.label = new_label.clone();
    storage::save_credential(env, credential_id, &credential);
    storage::bump_credential_ttl(env, credential_id);

    events::credential_label_updated(env, credential_id, new_label);

    Ok(())
}
