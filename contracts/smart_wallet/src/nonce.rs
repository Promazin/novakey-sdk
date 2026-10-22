//! Nonce management and replay-protection utilities.
//!
//! NovaKey uses a simple monotonic counter nonce stored in instance storage.
//! Every successful `__check_auth` call increments the nonce by one.
//!
//! # Replay attack surface
//! Without a nonce an attacker who captures a signed `AuthPayload` could
//! resubmit it on the network to repeat the same operation. The nonce closes
//! this window:
//!
//! 1. The SDK reads the current nonce via `SmartWalletContract::get_nonce`.
//! 2. The SDK embeds that nonce in the `SignaturePayload` before asking the
//!    device to sign.
//! 3. `__check_auth` rejects any payload whose nonce ≠ `current_nonce`.
//! 4. On success the nonce is incremented atomically within the same
//!    invocation, so the same payload can never be reused.
//!
//! # Sequence diagram
//! ```text
//! Client                     Relayer              Soroban
//!   │── get_nonce() ────────────────────────────►│
//!   │◄── current_nonce ──────────────────────────│
//!   │
//!   │── sign(nonce, op_hash) ──► device enclave
//!   │◄── secp256r1 signature ─── device enclave
//!   │
//!   │── AuthPayload{nonce, sig} ──► Relayer
//!                     │── fee_bump(tx) ─────────►│
//!                                    __check_auth │
//!                                    verify nonce │
//!                                    verify sig   │
//!                                    nonce += 1   │
//! ```

use soroban_sdk::Env;

use crate::{error::SmartWalletError, storage};

/// Atomically validate and advance the nonce.
///
/// Returns `Ok(next_nonce)` if `provided == current`, otherwise returns
/// [`SmartWalletError::InvalidNonce`].
///
/// The caller is responsible for persisting `next_nonce` only after all other
/// checks (signature verification) have passed.
pub fn consume_nonce(env: &Env, provided: u64) -> Result<u64, SmartWalletError> {
    let current = storage::get_nonce(env);

    if provided != current {
        return Err(SmartWalletError::InvalidNonce);
    }

    let next = current
        .checked_add(1)
        .ok_or(SmartWalletError::InvalidNonce)?; // u64 overflow guard

    storage::set_nonce(env, next);
    Ok(next)
}
