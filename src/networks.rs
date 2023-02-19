use eth2_network_config::Eth2NetworkConfig;
use types::{ChainSpec, GnosisEthSpec, MainnetEthSpec};

use crate::DepositError;

/// String representation for all supported networks
pub static SUPPORTED_NETWORKS: [&str; 5] = ["goerli", "prater", "mainnet", "gnosis", "minimal"];

#[derive(Clone)]
pub enum NetworkSpec {
    Mainnet,
    Goerli,
    Gnosis,
    Minimal,
}

/// Collects network spec from user or library inputs
impl TryFrom<String> for NetworkSpec {
    type Error = DepositError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let network = match value.as_str() {
            "mainnet" => NetworkSpec::Mainnet,
            "goerli" => NetworkSpec::Goerli,
            "prater" => NetworkSpec::Goerli,
            "gnosis" => NetworkSpec::Gnosis,
            "minimal" => NetworkSpec::Minimal,
            _ => {
                log::info!("Invalid network name passed: {value}");
                return Err(DepositError::InvalidNetworkName(
                    "Unknown network name passed".to_string(),
                ));
            }
        };
        Ok(network)
    }
}

/// Convert to a string that is recognizeable by Lighthouse's
/// Eth2NetworkConfig::constant
impl From<NetworkSpec> for &'static str {
    fn from(value: NetworkSpec) -> &'static str {
        match value {
            NetworkSpec::Mainnet => "mainnet",
            NetworkSpec::Goerli => "goerli",
            NetworkSpec::Gnosis => "gnosis",
            NetworkSpec::Minimal => "minimal",
        }
    }
}

/// Convert to Lighthouse internal spec repr.
/// Works only for public networks, private net needs
/// to load file.
impl From<NetworkSpec> for ChainSpec {
    fn from(value: NetworkSpec) -> ChainSpec {
        match value {
            NetworkSpec::Gnosis => Eth2NetworkConfig::constant(value.into())
                .unwrap()
                .unwrap()
                .chain_spec::<GnosisEthSpec>()
                .unwrap(),
            _ => Eth2NetworkConfig::constant(value.into())
                .unwrap()
                .unwrap()
                .chain_spec::<MainnetEthSpec>()
                .unwrap(),
        }
    }
}

impl NetworkSpec {
    /// Find out if the config for public network, or private net one
    pub fn is_public(&self) -> bool {
        !matches!(self, NetworkSpec::Minimal)
    }
}
