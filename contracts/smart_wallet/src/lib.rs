//! NovaKey Smart Wallet Contract
//!
//! This is the per-user Soroban smart contract that acts as a non-custodial
//! account. Authentication is performed via secp256r1 passkey signatures,
//! leveraging Stellar Protocol 21's native cryptographic host functions.
//!
//! # Architecture
//! Each user gets their own instance of this contract deployed by the Factory.
//! The contract stores the user's passkey credential (public key) and validates
//! every transaction against a fresh biometric signature from the user's device.

#![no_std]

mod contract;
mod error;
mod storage;
mod types;

pub use contract::SmartWalletContract;
pub use error::SmartWalletError;
pub use types::{Credential, SignaturePayload};
