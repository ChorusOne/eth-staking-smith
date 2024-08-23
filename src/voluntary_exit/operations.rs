use tree_hash::Hash256;
use types::{
    ChainSpec, Domain, ForkName, PublicKey, SignedRoot, SignedVoluntaryExit, VoluntaryExit,
};

use crate::beacon_node::BeaconNodeExportable;

pub(crate) trait SignedVoluntaryExitValidator {
    fn validate(self, pubkey: &PublicKey, spec: &ChainSpec, genesis_validators_root: &Hash256);
}

impl BeaconNodeExportable for SignedVoluntaryExit {
    fn export(&self) -> serde_json::Value {
        serde_json::json!({
            "message": {
                "epoch": self.message.epoch.as_u64(),
                "validator_index": self.message.validator_index,
            },
            "signature": self.signature.to_string()
        })
    }

    fn beacon_node_path(&self) -> String {
        "/eth/v1/beacon/pool/voluntary_exits".to_string()
    }
}

impl SignedVoluntaryExitValidator for SignedVoluntaryExit {
    fn validate(self, pubkey: &PublicKey, spec: &ChainSpec, genesis_validators_root: &Hash256) {
        let fork_name = spec.fork_name_at_epoch(self.message.epoch);
        let fork_version = match fork_name {
            ForkName::Base | ForkName::Altair | ForkName::Merge | ForkName::Capella => {
                spec.fork_version_for_name(fork_name)
            }
            // EIP-7044
            ForkName::Deneb => spec.fork_version_for_name(ForkName::Capella),
        };
        let domain = spec.compute_domain(
            Domain::VoluntaryExit,
            fork_version,
            *genesis_validators_root,
        );

        let voluntary_exit: VoluntaryExit = VoluntaryExit {
            validator_index: self.message.validator_index,
            epoch: self.message.epoch,
        };
        let signing_root = voluntary_exit.signing_root(domain);
        if !self.signature.verify(pubkey, signing_root) {
            panic!("Invalid voluntary exit signature")
        }
    }
}
