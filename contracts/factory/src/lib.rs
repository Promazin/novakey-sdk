//! NovaKey Factory Contract
//!
//! The Factory is a singleton contract deployed once per network. Its sole
//! responsibility is to deploy individual [`SmartWalletContract`] instances
//! deterministically so that a user's on-chain address is always derivable
//! from their credential ID without querying chain state.
//!
//! # Deterministic addressing
//! Soroban's `deployer().with_current_contract(salt)` API produces the same
//! contract address for a given (factory_address, salt) pair, regardless of
//! when it is called. We derive the salt from the user's credential ID:
//!
//! ```text
//! salt = SHA-256(credential_id)
//! ```
//!
//! This means the SDK can predict the wallet address client-side before the
//! deploy transaction is even submitted.

#![no_std]

mod contract;
mod error;
mod storage;

pub use contract::{FactoryContract, FactoryContractClient};
pub use error::FactoryError;
