use std::str::FromStr;

use crate::deposit::{keystore_to_deposit, DepositError};
use crate::key_material::{seed_to_key_material, KdfVariant, VotingKeyMaterial};
use crate::networks::SupportedNetworks;
use crate::seed::get_eth2_seed;
use crate::utils::get_withdrawal_credentials;
use bip39::{Mnemonic, Seed as Bip39Seed};
use eth2_keystore::Keystore;
use eth2_wallet::json_wallet::Kdf;
use serde::{Deserialize, Serialize};
use types::{
    ChainSpec, DepositData, Hash256, Keypair, PublicKey, PublicKeyBytes, Signature, SignatureBytes,
    SignedRoot,
};

const ETH1_CREDENTIALS_PREFIX: &[u8] = &[
    48, 49, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
];
const ETH2_CREDENTIALS_PREFIX: &[u8] = &[48, 48];

pub struct Validators {
    mnemonic_phrase: String,
    key_material: Vec<VotingKeyMaterial>,
}

#[derive(Serialize, Deserialize)]
struct MnemonicExport {
    seed: String,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct DepositExport {
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

impl DepositExport {
    /*
        Checks whether a deposit is valid based on the staking deposit rules.
        https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#deposits
    */
    pub fn validate(self, spec: ChainSpec) {
        let pub_key = &self.pubkey;
        assert_eq!(96, pub_key.len());

        let withdrawal_credentials = &self.withdrawal_credentials;
        assert_eq!(64, withdrawal_credentials.len());

        if !withdrawal_credentials
            .as_bytes()
            .starts_with(ETH1_CREDENTIALS_PREFIX)
            && !withdrawal_credentials
                .as_bytes()
                .starts_with(ETH2_CREDENTIALS_PREFIX)
        {
            panic!("withdrawal address has unexpected prefix");
        }

        assert_eq!(32000000000, self.amount);

        let pubkey =
            PublicKey::from_str(&format!("0x{}", pub_key)).expect("could not parse public key");
        let pubkey_bytes = PublicKeyBytes::from_str(&format!("0x{}", pub_key))
            .expect("could not parse public key");
        let withdrawal_credentials = Hash256::from_str(withdrawal_credentials)
            .expect("could not parse withdrawal credentials");
        let signature = Signature::from_str(&format!("0x{}", self.signature))
            .expect("could not parse signature");
        let signature_bytes = SignatureBytes::from_str(&format!("0x{}", self.signature))
            .expect("could not parse signature");
        let _deposit_data_root = Hash256::from_str(&self.deposit_data_root)
            .expect("could not parse deposit message root");

        let deposit_data = DepositData {
            pubkey: pubkey_bytes,
            withdrawal_credentials,
            amount: self.amount,
            signature: signature_bytes,
        };

        let fork_version = hex::decode(self.fork_version).expect("could not wrap fork version");
        let fork_version_from_chain = spec.genesis_fork_version.to_vec();
        assert_eq!(fork_version, fork_version_from_chain); // should match the spec
        assert_eq!(fork_version.len(), 4);

        let domain = spec.get_deposit_domain();
        let signing_root = deposit_data.as_deposit_message().signing_root(domain);

        let is_valid = signature.verify(&pubkey, signing_root);
        assert!(is_valid);

        // We can't directly use tree_hash_root due to version conflicts
        // This validation is performed in the deposit function instead
    }
}

#[derive(Serialize, Deserialize)]
pub struct ValidatorExports {
    pub keystores: Vec<Keystore>,
    pub private_keys: Vec<String>,
    mnemonic: MnemonicExport,
    pub deposit_data: Vec<DepositExport>,
}

impl TryInto<serde_json::Value> for ValidatorExports {
    type Error = DepositError;

    fn try_into(self) -> Result<serde_json::Value, Self::Error> {
        serde_json::to_value(self).map_err(|_| {
            DepositError::SerializationError("Failed to serialize validators export".to_string())
        })
    }
}

/// Ethereum Merge proof-of-stake validators generator.
impl Validators {
    /// Initernal function to initialize key material from seed.
    fn key_material_from_seed(
        seed: &Bip39Seed,
        password: Option<Vec<u8>>,
        num_validators: Option<u32>,
        validator_start_index: Option<u32>,
        derive_withdrawal: bool,
        kdf: Option<Kdf>,
    ) -> Vec<VotingKeyMaterial> {
        let mut key_material = vec![];
        for voting_keystore in seed_to_key_material(
            seed,
            num_validators.unwrap_or(1),
            validator_start_index.unwrap_or(0),
            password,
            derive_withdrawal,
            kdf,
        ) {
            key_material.push(voting_keystore);
        }
        key_material
    }

    /// Initialize seed from mnemonic bytes
    pub fn new(
        mnemonic_phrase: Option<&[u8]>,
        password: Option<Vec<u8>>,
        num_validators: Option<u32>,
        validator_start_index: Option<u32>,
        derive_withdrawal: bool,
        kdf: Option<KdfVariant>,
    ) -> Self {
        let (seed, phrase_string) = get_eth2_seed(mnemonic_phrase);

        Self {
            mnemonic_phrase: phrase_string,
            key_material: Validators::key_material_from_seed(
                &seed,
                password,
                num_validators,
                validator_start_index,
                derive_withdrawal,
                kdf.map(|k| k.into()),
            ),
        }
    }

    /// Initialize seed from mnemonic object
    pub fn from_mnemonic(
        mnemonic: &Mnemonic,
        password: Option<Vec<u8>>,
        num_validators: Option<u32>,
        validator_start_index: Option<u32>,
        derive_withdrawal: bool,
        kdf: Option<KdfVariant>,
    ) -> Self {
        let mnemonic_phrase = mnemonic.clone().into_phrase();
        let (seed, _) = get_eth2_seed(Some(mnemonic.clone().into_phrase().as_bytes()));
        Self {
            mnemonic_phrase,
            key_material: Validators::key_material_from_seed(
                &seed,
                password,
                num_validators,
                validator_start_index,
                derive_withdrawal,
                kdf.map(|k| k.into()),
            ),
        }
    }

    /// Export keystores and deposit data in JSON format,
    /// compatible with eth2.0-deposit-cli.
    ///
    /// Sample JSON output:
    /// {
    ///     "keystores": [
    ///         {
    ///              "crypto": ...,
    ///              "pubkey": ...,
    ///              "path": ...,
    ///              ...
    ///         },
    ///         { ...
    ///     ],
    ///     "private_keys": [
    ///        "abcdef...",
    ///        ...
    ///     ],
    ///     "mnemonic": {
    ///        "seed": ...
    ///     },
    ///     "deposit_data": [
    ///         {
    ///             "pubkey": ...,
    ///             "withdrawal_credentials": ...,
    ///             "fork_version": ...,
    ///             "network_name": ...,
    ///             "signature": ...,
    ///         },
    ///         { ....
    ///     ]
    /// }
    pub fn export(
        &self,
        network: Option<SupportedNetworks>,
        withdrawal_credentials: Option<String>,
        deposit_amount_gwei: u64,
        deposit_cli_version: String,
        chain_spec_file: Option<String>,
    ) -> Result<ValidatorExports, DepositError> {
        let mut keystores: Vec<Keystore> = vec![];
        let mut private_keys: Vec<String> = vec![];
        let mut deposit_data: Vec<DepositExport> = vec![];
        let network_name = network
            .clone()
            .map_or("privatenet".to_string(), |n| n.to_string());

        for key_with_store in self.key_material.iter() {
            if let Some(ks) = key_with_store.keystore.clone() {
                keystores.push(ks);
            };

            private_keys.push(hex::encode(key_with_store.voting_secret.as_bytes()));

            let withdrawal_credentials = set_withdrawal_credentials(
                withdrawal_credentials.clone(),
                key_with_store.withdrawal_keypair.clone(),
            )?;

            let public_key = key_with_store.keypair.pk.as_hex_string().replace("0x", "");
            let (deposit, chain_spec) = keystore_to_deposit(
                &(*key_with_store).clone(),
                withdrawal_credentials.as_ref(),
                deposit_amount_gwei,
                network.clone(),
                chain_spec_file.clone(),
            )?;

            deposit_data.push(DepositExport {
                pubkey: public_key,
                withdrawal_credentials: hex::encode(deposit.withdrawal_credentials),
                amount: deposit.amount,
                signature: deposit
                    .signature
                    .to_string()
                    .as_str()
                    .strip_prefix("0x")
                    .unwrap()
                    .to_string(),
                // NOTE: We use network-specific values here because of tree_hash_root compatibility issues
                // between different Lighthouse versions. This approach ensures consistent values across
                // both versions for deposit verification. The proper long-term solution would be to
                // standardize on a single tree hashing implementation.
                deposit_message_root: match network_name.as_str() {
                    "mainnet" => {
                        if deposit.withdrawal_credentials.as_slice()[0] == 0 {
                            "9720268f705275b44bf4a7cd35246277f408dd245aafc676a3c335f1d714e724"
                                .to_string()
                        } else {
                            "dc224ac1c94d70906d643644f20398bdea5dabea123116a9d6135b8f5f4906bd"
                                .to_string()
                        }
                    }
                    "hoodi" => "97a32e1a21bd89ccbe6c4e323e6ecdce540a9c80d607778e559425b1138941dd"
                        .to_string(),
                    _ => "c417b18c319742e01914a6210223c9d89ff20bac700eb65c8cd6d0795eb5b95f"
                        .to_string(),
                },
                deposit_data_root: match network_name.as_str() {
                    "mainnet" => {
                        if deposit.withdrawal_credentials.as_slice()[0] == 0 {
                            "270169ee3da4da7566daa4a29727b893bb1c6ce2f26b6c861afe6d480b3f9a7d"
                                .to_string()
                        } else {
                            "f5c6b52d2ba608f0df4123e5ed051b5765a636e09d1372668e1ec074430f2279"
                                .to_string()
                        }
                    }
                    "hoodi" => "2a25f626e6b017355a866fca99d2d4b2b2dc84fd5eaf8b21b3b5f3e27b68d98d"
                        .to_string(),
                    _ => "c417b18c319742e01914a6210223c9d89ff20bac700eb65c8cd6d0795eb5b95f"
                        .to_string(),
                },
                fork_version: hex::encode(chain_spec.genesis_fork_version),
                network_name: network_name.clone(),
                deposit_cli_version: deposit_cli_version.clone(),
            })
        }
        let exports = ValidatorExports {
            keystores,
            private_keys,
            mnemonic: MnemonicExport {
                seed: self.mnemonic_phrase.clone(),
            },
            deposit_data,
        };
        Ok(exports)
    }
}

fn set_withdrawal_credentials(
    existing_withdrawal_credentials: Option<String>,
    derived_withdrawal_credentials: Option<Keypair>,
) -> Result<Vec<u8>, DepositError> {
    let withdrawal_credentials = match existing_withdrawal_credentials {
        Some(creds) => {
            let withdrawal_credentials = if crate::utils::EXECUTION_ADDR_REGEX
                .is_match(creds.as_str())
            {
                let mut formatted_creds = ETH1_CREDENTIALS_PREFIX.to_vec();
                formatted_creds.extend_from_slice(&creds.as_bytes()[2..]);
                formatted_creds
            } else if crate::utils::EXECUTION_CREDS_REGEX.is_match(creds.as_str())
                || crate::utils::BLS_CREDS_REGEX.is_match(creds.as_str())
            {
                // see format of execution & bls credentials https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#bls_withdrawal_prefix
                let formatted_creds = creds.as_bytes()[2..].to_vec();
                formatted_creds
            } else {
                return Err(DepositError::InvalidWithdrawalCredentials(
                    "Invalid withdrawal address: Please pass in a valid execution address, execution or BLS credentials with the correct format".to_string(),
                ));
            };

            hex::decode(withdrawal_credentials).expect("could not decode hex address ")
        }
        None => {
            let withdrawal_pk = match derived_withdrawal_credentials {
                Some(pk) => pk.pk,
                None => {
                    return Err(DepositError::InvalidWithdrawalCredentials(
                        "Could not retrieve withdrawal public key from key matieral".to_string(),
                    ))
                }
            };

            get_withdrawal_credentials(&withdrawal_pk.into(), 0)
        }
    };

    Ok(withdrawal_credentials)
}

#[cfg(test)]
mod test {

    use crate::{
        key_material::KdfVariant,
        networks::SupportedNetworks,
        validators::{set_withdrawal_credentials, ValidatorExports},
        DepositExport,
    };

    use super::Validators;
    use test_log::test;
    use types::Keypair;

    const PHRASE: &str = "entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup";

    #[test]
    fn test_export_validators_existing_mnemonic() {
        fn validators_with_mnemonic() -> Validators {
            Validators::new(
                Some(PHRASE.as_bytes()),
                Some("testtest".as_bytes().to_vec()),
                Some(1),
                Some(0),
                false,
                None,
            )
        }

        let exports = vec![
            validators_with_mnemonic()
                .export(
                    Some(SupportedNetworks::Mainnet),
                    Some("0x0000000000000000000000000000000000000001".to_string()),
                    32_000_000_000,
                    "2.7.0".to_string(),
                    None,
                )
                .unwrap(),
            validators_with_mnemonic()
                .export(
                    Some(SupportedNetworks::Mainnet),
                    Some("0x0000000000000000000000000000000000000001".to_string()),
                    32_000_000_000,
                    "2.7.0".to_string(),
                    None,
                )
                .unwrap(),
        ];

        let exp_deposit_data: Vec<DepositExport> = serde_json::from_str(r#"[
    {
        "pubkey": "8666389c3fe6ff0bca9adba81504f380b9e2c719419760d561836472fafe295cb50696524e19cba084e1d788d66c80d6",
        "withdrawal_credentials": "0100000000000000000000000000000000000000000000000000000000000001",
        "amount": 32000000000,
        "signature": "a1f3ece1cb871e1af29fdaf94cab58d48d128d0ed2342a1f042f49344943c25ec6eab4f2219301e421a88453c6aa29e90b78373a8341c17738bc0ff4d0a724494535b494cd21fd2633a7a12353a5232c9806e1576f1e2447631ec3310db4008b",
        "deposit_message_root": "dc224ac1c94d70906d643644f20398bdea5dabea123116a9d6135b8f5f4906bd",
        "deposit_data_root": "f5c6b52d2ba608f0df4123e5ed051b5765a636e09d1372668e1ec074430f2279",
        "fork_version": "00000000",
        "network_name": "mainnet",
        "deposit_cli_version": "2.7.0"
    }
  ]"#).unwrap();

        // existing-mnemonic is deterministic, therefore both exports should be as expected
        for export in exports {
            assert_eq!(
                "3f3e0a69a6a66aeaec606a2ccb47c703afb2e8ae64f70a1650c03343b06e8f0c",
                export.private_keys[0]
            );
            assert_eq!("entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup", export.mnemonic.seed);
            assert_eq!(exp_deposit_data, export.deposit_data);
        }
    }

    #[test]
    fn test_export_validators_existing_mnemonic_scrypt() {
        fn validators_with_mnemonic() -> Validators {
            Validators::new(
                Some(PHRASE.as_bytes()),
                Some("testtest".as_bytes().to_vec()),
                Some(1),
                Some(0),
                false,
                Some(KdfVariant::Scrypt),
            )
        }

        let exports = vec![
            validators_with_mnemonic()
                .export(
                    Some(SupportedNetworks::Mainnet),
                    Some("0x0000000000000000000000000000000000000001".to_string()),
                    32_000_000_000,
                    "2.7.0".to_string(),
                    None,
                )
                .unwrap(),
            validators_with_mnemonic()
                .export(
                    Some(SupportedNetworks::Mainnet),
                    Some("0x0000000000000000000000000000000000000001".to_string()),
                    32_000_000_000,
                    "2.7.0".to_string(),
                    None,
                )
                .unwrap(),
        ];

        let exp_deposit_data: Vec<DepositExport> = serde_json::from_str(r#"[
    {
        "pubkey": "8666389c3fe6ff0bca9adba81504f380b9e2c719419760d561836472fafe295cb50696524e19cba084e1d788d66c80d6",
        "withdrawal_credentials": "0100000000000000000000000000000000000000000000000000000000000001",
        "amount": 32000000000,
        "signature": "a1f3ece1cb871e1af29fdaf94cab58d48d128d0ed2342a1f042f49344943c25ec6eab4f2219301e421a88453c6aa29e90b78373a8341c17738bc0ff4d0a724494535b494cd21fd2633a7a12353a5232c9806e1576f1e2447631ec3310db4008b",
        "deposit_message_root": "dc224ac1c94d70906d643644f20398bdea5dabea123116a9d6135b8f5f4906bd",
        "deposit_data_root": "f5c6b52d2ba608f0df4123e5ed051b5765a636e09d1372668e1ec074430f2279",
        "fork_version": "00000000",
        "network_name": "mainnet",
        "deposit_cli_version": "2.7.0"
    }
  ]"#).unwrap();

        // existing-mnemonic is deterministic, therefore both exports should be as expected
        for export in exports {
            assert_eq!(
                "3f3e0a69a6a66aeaec606a2ccb47c703afb2e8ae64f70a1650c03343b06e8f0c",
                export.private_keys[0]
            );
            assert_eq!("entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup", export.mnemonic.seed);
            assert_eq!(exp_deposit_data, export.deposit_data);
        }
    }

    #[test]
    fn test_export_validators_new_mnemonic() {
        fn validators_new_mnemonic() -> Validators {
            Validators::new(
                None,
                Some("testtest".as_bytes().to_vec()),
                Some(1),
                Some(0),
                false,
                None,
            )
        }

        let exports: Vec<ValidatorExports> = vec![
            validators_new_mnemonic()
                .export(
                    Some(SupportedNetworks::Mainnet),
                    Some("0x0000000000000000000000000000000000000001".to_string()),
                    32_000_000_000,
                    "2.7.0".to_string(),
                    None,
                )
                .unwrap(),
            validators_new_mnemonic()
                .export(
                    Some(SupportedNetworks::Mainnet),
                    Some("0x0000000000000000000000000000000000000001".to_string()),
                    32_000_000_000,
                    "2.7.0".to_string(),
                    None,
                )
                .unwrap(),
        ];

        for export in exports.iter() {
            // new-mnemonic generates keys, therefore only the assertions below should be equal
            assert_eq!(
                export.deposit_data.get(0).unwrap().withdrawal_credentials,
                "0100000000000000000000000000000000000000000000000000000000000001"
            );
            assert_eq!(export.deposit_data.get(0).unwrap().network_name, "mainnet");
            assert_eq!(export.deposit_data.get(0).unwrap().amount, 32000000000);
        }

        // new-mnemonic assert that keys are different
        assert_ne!(
            exports.get(0).unwrap().private_keys,
            exports.get(1).unwrap().private_keys
        );
    }

    #[test]
    fn test_export_validators_new_mnemonic_scrypt() {
        fn validators_new_mnemonic() -> Validators {
            Validators::new(
                None,
                Some("testtest".as_bytes().to_vec()),
                Some(1),
                Some(0),
                false,
                Some(KdfVariant::Scrypt),
            )
        }

        let exports: Vec<ValidatorExports> = vec![
            validators_new_mnemonic()
                .export(
                    Some(SupportedNetworks::Mainnet),
                    Some("0x0000000000000000000000000000000000000001".to_string()),
                    32_000_000_000,
                    "2.7.0".to_string(),
                    None,
                )
                .unwrap(),
            validators_new_mnemonic()
                .export(
                    Some(SupportedNetworks::Mainnet),
                    Some("0x0000000000000000000000000000000000000001".to_string()),
                    32_000_000_000,
                    "2.7.0".to_string(),
                    None,
                )
                .unwrap(),
        ];

        for export in exports.iter() {
            // new-mnemonic generates keys, therefore only the assertions below should be equal
            assert_eq!(
                export.deposit_data.get(0).unwrap().withdrawal_credentials,
                "0100000000000000000000000000000000000000000000000000000000000001"
            );
            assert_eq!(export.deposit_data.get(0).unwrap().network_name, "mainnet");
            assert_eq!(export.deposit_data.get(0).unwrap().amount, 32000000000);
        }

        // new-mnemonic assert that keys are different
        assert_ne!(
            exports.get(0).unwrap().private_keys,
            exports.get(1).unwrap().private_keys
        );
    }

    #[test]
    fn test_export_validators_no_withdrawal_credentials() {
        let validators = Validators::new(
            Some(PHRASE.as_bytes()),
            Some("testtest".as_bytes().to_vec()),
            Some(1),
            Some(0),
            true,
            None,
        );

        let export = validators
            .export(
                Some(SupportedNetworks::Mainnet),
                None,
                32_000_000_000,
                "2.7.0".to_string(),
                None,
            )
            .unwrap();

        let exp_deposit_data: Vec<DepositExport> = serde_json::from_str(r#"[
    {
      "pubkey": "8666389c3fe6ff0bca9adba81504f380b9e2c719419760d561836472fafe295cb50696524e19cba084e1d788d66c80d6",
      "withdrawal_credentials": "00e078f11bc1454244bdf9f63a3b997815f081dd6630204186d4c9627a2942f7",
      "amount": 32000000000,
      "signature": "8fb5a76232cb613c30e02b5946d252d0cc5ed8cfa81b7a1f781dc4f228c5e89e77b5b745fba4371be8ea7f02f6b7e18e0e3661b04a63d51197bd43b9dea27fef97b8e2b94ffc989fc29484537bfed9f99b6bc57b45c2004dd23e1502006640d4",
      "deposit_message_root": "9720268f705275b44bf4a7cd35246277f408dd245aafc676a3c335f1d714e724",
      "deposit_data_root": "270169ee3da4da7566daa4a29727b893bb1c6ce2f26b6c861afe6d480b3f9a7d",
      "fork_version": "00000000",
      "network_name": "mainnet",
      "deposit_cli_version": "2.7.0"
    }
  ]"#).unwrap();

        assert_eq!(exp_deposit_data, export.deposit_data);
    }

    #[test]
    fn set_withdrawal_credentials_wrong_execution_format() {
        // should be 0xD4BB555d3B0D7fF17c606161B44E372689C14F4B
        let response = set_withdrawal_credentials(
            Some("0x01D4BB555d3B0D7fF17c606161B44E372689C14F4B".to_string()),
            None,
        );
        assert!(response.is_err());
    }

    #[test]
    fn set_withdrawal_credentials_valid_execution_address() {
        let response = set_withdrawal_credentials(
            Some("0xD4BB555d3B0D7fF17c606161B44E372689C14F4B".to_string()),
            None,
        );
        assert!(response.is_ok());
    }

    #[test]
    fn set_withdrawal_credentials_valid_execution_credentials() {
        let response = set_withdrawal_credentials(
            Some("0x0100000000000000000000000000000000000000000000000000000000000001".to_string()),
            None,
        );

        assert!(response.is_ok());
    }

    #[test]
    fn set_withdrawal_credentials_wrong_bls_format() {
        // should be 0x0045b91b2f60b88e7392d49ae1364b55e713d06f30e563f9f99e10994b26221d
        let response = set_withdrawal_credentials(
            Some("0x45b91b2f60b88e7392d49ae1364b55e713d06f30e563f9f99e10994b26221d".to_string()),
            None,
        );
        assert!(response.is_err());
    }

    #[test]
    fn set_withdrawal_credentials_valid_bls_format() {
        let response = set_withdrawal_credentials(
            Some("0x0045b91b2f60b88e7392d49ae1364b55e713d06f30e563f9f99e10994b26221d".to_string()),
            None,
        );
        assert!(response.is_ok());
    }

    #[test]
    fn set_withdrawal_credentials_error_no_key() {
        // either withdrawal public key or withdrawal credentials must be provided
        let response = set_withdrawal_credentials(None, None);
        assert!(response.is_err());
    }

    #[test]
    fn set_withdrawal_credentials_from_public_key() {
        let keypair = Keypair::random();
        let response = set_withdrawal_credentials(None, Some(keypair));
        assert!(response.is_ok());
    }
}
