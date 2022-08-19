pub(crate) mod deposit;
pub(crate) mod keystore;
pub(crate) mod utils;
pub mod validators;
pub(crate) mod wallet;

pub use deposit::DepositError;
pub use validators::*;

#[macro_use]
extern crate lazy_static;
