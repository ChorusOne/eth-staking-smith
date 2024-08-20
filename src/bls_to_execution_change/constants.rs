use std::collections::HashMap;

use lazy_static::lazy_static;
use types::Hash256;

use crate::networks::SupportedNetworks;

fn decode_genesis_validators_root(hex_value: &str) -> Hash256 {
    Hash256::from_slice(hex::decode(hex_value).unwrap().as_slice())
}

// Genesis validators root values are not present in chain spec,
// but instead acquired from genesis. The values below are well-known
// and taken from repositories in https://github.com/eth-clients organization.
lazy_static! {
    pub static ref GENESIS_VALIDATORS_ROOT_MAINNET: Hash256 = decode_genesis_validators_root(
        "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
    );
    pub static ref GENESIS_VALIDATORS_ROOT_HOLESKY: Hash256 = decode_genesis_validators_root(
        "9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1"
    );
    pub static ref GENESIS_VALIDATORS_ROOT_GOERLI: Hash256 = decode_genesis_validators_root(
        "043db0d9a83813551ee2f33450d23797757d430911a9320530ad8a0eabc43efb"
    );
    pub static ref GENESIS_VALIDATOR_ROOT: HashMap<SupportedNetworks, Hash256> = HashMap::from([
        (
            SupportedNetworks::Mainnet,
            GENESIS_VALIDATORS_ROOT_MAINNET.to_owned()
        ),
        (
            SupportedNetworks::Prater,
            GENESIS_VALIDATORS_ROOT_GOERLI.to_owned()
        ),
        (
            SupportedNetworks::Goerli,
            GENESIS_VALIDATORS_ROOT_GOERLI.to_owned()
        ),
        (
            SupportedNetworks::Holesky,
            GENESIS_VALIDATORS_ROOT_HOLESKY.to_owned()
        ),
    ]);
}

pub(crate) fn validators_root_for(network: &SupportedNetworks) -> Hash256 {
    *GENESIS_VALIDATOR_ROOT.get(network).unwrap()
}
