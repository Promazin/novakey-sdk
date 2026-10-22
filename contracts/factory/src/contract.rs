use soroban_sdk::{contract, contractimpl, Address, BytesN, Env};

use crate::{error::FactoryError, storage};

#[contract]
pub struct FactoryContract;

#[contractimpl]
impl FactoryContract {
    /// Returns the factory contract version.
    pub fn version(_env: Env) -> u32 {
        1
    }
}
