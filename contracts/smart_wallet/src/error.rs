use soroban_sdk::contracterror;

/// All error codes emitted by the SmartWallet contract.
///
/// These map directly to Soroban u32 error codes returned in the
/// invocation result envelope, giving SDK consumers structured error
/// handling rather than opaque failures.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum SmartWalletError {
    /// Caller attempted to re-initialise an already-initialised wallet.
    AlreadyInitialized = 1,
    /// The wallet has not been initialised yet.
    NotInitialized = 2,
    /// No credential with the given key ID is registered.
    CredentialNotFound = 3,
    /// A credential with this key ID already exists.
    CredentialAlreadyExists = 4,
    /// The secp256r1 signature provided does not verify against the stored key.
    InvalidSignature = 5,
    /// The nonce in the signed payload does not match the contract's nonce.
    InvalidNonce = 6,
    /// The operation hash in the payload does not match the actual operation.
    InvalidOperationHash = 7,
    /// The credential label exceeds the maximum allowed length.
    LabelTooLong = 8,
    /// Maximum number of credentials per wallet has been reached.
    MaxCredentialsReached = 9,
}
