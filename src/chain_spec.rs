use std::path::Path;

use eth2_network_config::Eth2NetworkConfig;
use types::{ChainSpec, Config, GnosisEthSpec, Hash256, MainnetEthSpec, MinimalEthSpec};

use crate::{networks::SupportedNetworks, DepositError};

pub fn chain_spec_for_network(network: &SupportedNetworks) -> Result<ChainSpec, DepositError> {
    let network_name = network.to_string();
    if ["sepolia", "mainnet", "holesky", "hoodi"].contains(&network_name.as_str()) {
        match Eth2NetworkConfig::constant(&network_name) {
            Ok(Some(net_config)) => match net_config.chain_spec::<MainnetEthSpec>() {
                Ok(spec) => Ok(spec),
                Err(e) => {
                    Err(DepositError::InvalidNetworkName(format!(
                        "error creating chain spec for {network_name}: {e:?}"
                    )))
                }
            },
            Ok(None) => {
                Err(DepositError::InvalidNetworkName(format!(
                    "network not found: {network_name}"
                )))
            },
            Err(e) => {
                Err(DepositError::InvalidNetworkName(format!(
                    "network configuration error: {network_name}: {e}"
                )))
            }
        }
    } else if network_name.as_str() == "gnosis" {
        match Eth2NetworkConfig::constant(&network_name) {
            Ok(Some(net_config)) => match net_config.chain_spec::<GnosisEthSpec>() {
                Ok(spec) => Ok(spec),
                Err(e) => {
                    Err(DepositError::InvalidNetworkName(format!(
                        "error creating chain spec for {network_name}: {e:?}"
                    )))
                }
            },
            Ok(None) => {
                Err(DepositError::InvalidNetworkName(format!(
                    "network not found: {network_name}"
                )))
            },
            Err(e) => {
                Err(DepositError::InvalidNetworkName(format!(
                    "network configuration error: {network_name}: {e}"
                )))
            }
        }
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

pub fn validators_root_and_spec(
    chain: Option<SupportedNetworks>,
    testnet_properties: Option<(String, String)>,
) -> (Hash256, ChainSpec) {
    if chain.is_some() {
        let well_known_chain = chain.unwrap();
        (
            crate::networks::validators_root_for(&well_known_chain),
            chain_spec_for_network(&well_known_chain).expect("Invalid chain spec"),
        )
    } else {
        let (genesis_validators_root_str, testnet_config_path) = testnet_properties.expect(
            "If custom testnet config is passed, genesis validators root value must be included",
        );
        let genesis_validators_root_bytes = hex::decode(
            genesis_validators_root_str
                .strip_prefix("0x")
                .unwrap_or(&genesis_validators_root_str),
        )
        .expect("Invalid custom genesis validators root");
        (
            Hash256::from_slice(genesis_validators_root_bytes.as_slice()),
            chain_spec_from_file(testnet_config_path).expect("Invalid chain spec in file"),
        )
    }
}
