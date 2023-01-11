mod bls_to_execution_change;
mod existing_mnemonic;
mod new_mnemonic;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct DepositDataJson {
    pub pubkey: String,
    pub withdrawal_credentials: String,
    pub amount: u64,
    pub signature: String,
    pub deposit_message_root: String,
    pub deposit_data_root: String,
    pub fork_version: String,
    pub network_name: String,
    pub deposit_cli_version: String,
}
