use soroban_sdk::contracterror;

/// All error codes emitted by the Factory contract.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum FactoryError {
    /// Factory has already been initialised with a wallet WASM hash.
    AlreadyInitialized = 1,
    /// Factory has not been initialised yet.
    NotInitialized = 2,
    /// A wallet for this credential ID has already been deployed.
    WalletAlreadyExists = 3,
    /// The WASM hash provided during initialisation is zero / invalid.
    InvalidWasmHash = 4,
}
