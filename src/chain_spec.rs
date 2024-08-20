use std::path::Path;

use eth2_network_config::Eth2NetworkConfig;
use types::{ChainSpec, Config, MainnetEthSpec, MinimalEthSpec};

use crate::{networks::SupportedNetworks, DepositError};

pub fn chain_spec_for_network(network: &SupportedNetworks) -> Result<ChainSpec, DepositError> {
    let network_name = network.to_string();
    if ["goerli", "prater", "mainnet", "holesky"].contains(&network_name.as_str()) {
        Ok(Eth2NetworkConfig::constant(&network_name)
            .unwrap()
            .unwrap()
            .chain_spec::<MainnetEthSpec>()
            .unwrap())
    } else {
        Err(DepositError::InvalidNetworkName(format!(
            "unknown chain name: {network_name}"
        )))
    }
}

pub fn chain_spec_from_file(chain_spec_file: String) -> Result<ChainSpec, DepositError> {
    match Config::from_file(Path::new(chain_spec_file.as_str())) {
        Ok(cfg) => {
            let spec = if cfg.preset_base == "minimal" {
                cfg.apply_to_chain_spec::<MinimalEthSpec>(&ChainSpec::minimal())
                    .unwrap()
            } else {
                cfg.apply_to_chain_spec::<MainnetEthSpec>(&ChainSpec::mainnet())
                    .unwrap()
            };
            Ok(spec)
        }
        Err(e) => {
            log::error!("Unable to load chain spec config: {:?}", e);
            Err(DepositError::NoCustomConfig(
                "Can not parse config file for custom network config".to_string(),
            ))
        }
    }
}
