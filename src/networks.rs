use std::collections::HashMap;

use lazy_static::lazy_static;
use types::Hash256;

#[derive(clap::ValueEnum, Clone, Hash, Eq, PartialEq)]
pub enum SupportedNetworks {
    Mainnet,
    Holesky,
    Gnosis,
    // These are legacy networks they are supported on best effort basis
    Prater,
    Goerli,
}

impl std::fmt::Display for SupportedNetworks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SupportedNetworks::Mainnet => "mainnet",
            SupportedNetworks::Holesky => "holesky",
            SupportedNetworks::Prater => "goerli",
            SupportedNetworks::Goerli => "goerli",
            SupportedNetworks::Gnosis => "gnosis",
        };
        write!(f, "{}", s)
    }
}

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
    pub static ref GENESIS_VALIDATORS_ROOT_GNOSIS: Hash256 = decode_genesis_validators_root(
        "f5dcb5564e829aab27264b9becd5dfaa017085611224cb3036f573368dbb9d47"
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
        (
            SupportedNetworks::Gnosis,
            GENESIS_VALIDATORS_ROOT_GNOSIS.to_owned()
        )
    ]);
}

pub(crate) fn validators_root_for(network: &SupportedNetworks) -> Hash256 {
    *GENESIS_VALIDATOR_ROOT.get(network).unwrap()
}
