#![forbid(unsafe_code)]
pub mod bls_to_execution_change;
pub mod chain_spec;
pub mod cli;
pub(crate) mod deposit;
pub(crate) mod key_material;
pub mod networks;
pub(crate) mod seed;
pub(crate) mod utils;
pub mod validators;

pub use deposit::DepositError;
pub use validators::*;

#[macro_use]
extern crate serde_derive;
