use std::str::FromStr;

use types::{
    BlsToExecutionChange, ChainSpec, Domain, Hash256, PublicKey, SignedBlsToExecutionChange,
    SignedRoot,
};

use crate::{beacon_node::BeaconNodeExportable, utils::get_withdrawal_credentials};

pub(crate) trait SignedBlsToExecutionChangeValidator {
    fn validate(
        self,
        from_bls_withdrawal_credentials: &str,
        to_execution_address: &str,
        spec: &ChainSpec,
        genesis_validators_root: &Hash256,
    );
}

impl BeaconNodeExportable for SignedBlsToExecutionChange {
    fn export(&self) -> serde_json::Value {
        serde_json::json!([
            {
                "message": {
                    "validator_index": self.message.validator_index.to_string(),
                    "from_bls_pubkey": self.message.from_bls_pubkey,
                    "to_execution_address": format!("0x{}", hex::encode(self.message.to_execution_address)),
                },
                "signature": self.signature.to_string()
            }
        ])
    }

    fn beacon_node_path(&self) -> String {
        "/eth/v1/beacon/pool/bls_to_execution_changes".to_string()
    }
}

impl SignedBlsToExecutionChangeValidator for SignedBlsToExecutionChange {
    fn validate(
        self,
        from_bls_withdrawal_credentials: &str,
        execution_address: &str,
        spec: &ChainSpec,
        genesis_validators_root: &Hash256,
    ) {
        // execution address is same as input
        let msg_execution_address = &self.message.to_execution_address;
        assert_eq!(
            execution_address.to_lowercase(),
            format!("0x{}", hex::encode(msg_execution_address))
        );

        // withdrawal credentials are the same as input
        let withdrawal_pubkey = &self.message.from_bls_pubkey;
        let withdrawal_pubkey = PublicKey::from_str(&withdrawal_pubkey.to_string()).unwrap();

        let withdrawal = get_withdrawal_credentials(&withdrawal_pubkey.clone().into(), 0);
        let withdrawal_credentials = hex::encode(withdrawal);
        let withdrawal_credentials =
            std::str::from_utf8(withdrawal_credentials.as_bytes()).unwrap();

        assert_eq!(
            from_bls_withdrawal_credentials,
            format!("0x{}", withdrawal_credentials)
        );

        // verify signature
        // Clone the genesis_validators_root to match expected type
        let genesis_validators_root_clone = *genesis_validators_root;
        let domain = spec.compute_domain(
            Domain::BlsToExecutionChange,
            spec.genesis_fork_version,
            genesis_validators_root_clone,
        );

        let bls_to_execution_change: BlsToExecutionChange = BlsToExecutionChange {
            validator_index: self.message.validator_index,
            from_bls_pubkey: withdrawal_pubkey.clone().into(),
            to_execution_address: self.message.to_execution_address,
        };
        let signing_root = bls_to_execution_change.signing_root(domain);
        if !self.signature.verify(&withdrawal_pubkey, signing_root) {
            panic!("Invalid bls to execution change signature")
        }
    }
}
