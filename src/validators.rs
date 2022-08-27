use crate::deposit::{keystore_to_deposit, DepositError};
use crate::keystore::{seed_to_keystores, KeyMaterial};
use crate::seed::get_eth2_seed;
use bip39::{Mnemonic, Seed as Bip39Seed};
use eth2_keystore::Keystore;
use serde::{Deserialize, Serialize};
use tree_hash::TreeHash;

pub struct Validators<'a> {
    mnemonic_phrase: String,
    key_material: Vec<KeyMaterial>,
    password: &'a [u8],
}

#[derive(Serialize, Deserialize)]
struct MnemonicExport {
    seed: String,
}

#[derive(Serialize, Deserialize)]
struct DepositExport {
    pubkey: String,
    withdrawal_credentials: String,
    amount: u64,
    signature: String,
    deposit_message_root: String,
    deposit_data_root: String,
    fork_version: String,
    network_name: String,
    deposit_cli_version: String,
}

#[derive(Serialize, Deserialize)]
struct ValidatorExports {
    keystores: Vec<Keystore>,
    private_keys: Vec<String>,
    mnemonic: MnemonicExport,
    deposit_data: Vec<DepositExport>,
}

/// Ethereum Merge proof-of-stake validators generator.
impl<'a> Validators<'a> {
    /// Initernal function to initialize key material from seed.
    fn key_material_from_seed(
        seed: &'a Bip39Seed,
        password: &'a [u8],
        num_validators: Option<u32>,
        derive_withdrawal: bool,
    ) -> Vec<KeyMaterial> {
        let mut key_material = vec![];
        for voting_keystore in seed_to_keystores(
            seed,
            num_validators.unwrap_or(1),
            password,
            derive_withdrawal,
        ) {
            key_material.push(voting_keystore);
        }
        key_material
    }

    /// Initialize seed from mnemonic bytes
    pub fn new(
        mnemonic_phrase: Option<&[u8]>,
        password: &'a [u8],
        num_validators: Option<u32>,
        derive_withdrawal: bool,
    ) -> Self {
        let (seed, phrase_string) = get_eth2_seed(mnemonic_phrase);

        Self {
            mnemonic_phrase: phrase_string,
            key_material: Validators::key_material_from_seed(
                &seed,
                password,
                num_validators,
                derive_withdrawal,
            ),
            password,
        }
    }

    /// Initialize seed from mnemonic object
    pub fn from_mnemonic(
        mnemonic: &'a Mnemonic,
        password: &'a [u8],
        num_validators: Option<u32>,
        derive_withdrawal: bool,
    ) -> Self {
        let mnemonic_phrase = mnemonic.clone().into_phrase();
        let (seed, _) = get_eth2_seed(Some(mnemonic.clone().into_phrase().as_str().as_bytes()));
        Self {
            mnemonic_phrase,
            key_material: Validators::key_material_from_seed(
                &seed,
                password,
                num_validators,
                derive_withdrawal,
            ),
            password,
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
        network: String,
        withdrawal_credentials: Option<&str>,
        deposit_amount_gwei: u64,
        deposit_cli_version: String,
        chain_spec_file: Option<String>,
    ) -> Result<String, DepositError> {
        let mut keystores: Vec<Keystore> = vec![];
        let mut private_keys: Vec<String> = vec![];
        let mut deposit_data: Vec<DepositExport> = vec![];

        for key_with_store in self.key_material.iter() {
            let keystore = key_with_store.keystore.clone();
            keystores.push(keystore.clone());
            private_keys.push(hex::encode(key_with_store.voting_secret.as_bytes()));

            let withdrawal_credentials = if withdrawal_credentials.is_some() {
                Some(withdrawal_credentials.as_ref().unwrap().as_bytes())
            } else {
                None
            };
            let public_key = keystore.pubkey().to_string();
            let (deposit, chain_spec) = keystore_to_deposit(
                keystore.clone(),
                self.password,
                withdrawal_credentials,
                key_with_store.withdrawal_pk.clone(),
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
                deposit_message_root: hex::encode(deposit.as_deposit_message().tree_hash_root()),
                deposit_data_root: hex::encode(deposit.tree_hash_root()),
                fork_version: hex::encode(chain_spec.genesis_fork_version),
                network_name: network.clone(),
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
        Ok(serde_json::to_string_pretty(&exports).expect("Failed to serialize validators export"))
    }
}

#[cfg(test)]
mod test {

    use crate::validators::ValidatorExports;

    use super::Validators;
    use test_log::test;

    const PHRASE: &str = "entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup";

    #[test]
    fn test_export_validators_existing_mnemonic() {
        fn validators_with_mnemonic() -> Validators<'static> {
            Validators::new(Some(PHRASE.as_bytes()), "test".as_bytes(), Some(1), false)
        }

        let exports = vec![
            validators_with_mnemonic()
                .export(
                    "mainnet".to_string(),
                    Some("0100000000000000000000000000000000000000000000000000000000000001"),
                    32_000_000_000,
                    "2.3.0".to_string(),
                    None,
                )
                .unwrap(),
            validators_with_mnemonic()
                .export(
                    "mainnet".to_string(),
                    Some("0100000000000000000000000000000000000000000000000000000000000001"),
                    32_000_000_000,
                    "2.3.0".to_string(),
                    None,
                )
                .unwrap(),
        ];

        let expect_pks = r#""private_keys": [
    "3f3e0a69a6a66aeaec606a2ccb47c703afb2e8ae64f70a1650c03343b06e8f0c"
  ],"#;

        let expect_mnemonic = r#""mnemonic": {
    "seed": "entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup"
  },"#;

        let expect_deposit_data = r#""deposit_data": [
    {
      "pubkey": "8666389c3fe6ff0bca9adba81504f380b9e2c719419760d561836472fafe295cb50696524e19cba084e1d788d66c80d6",
      "withdrawal_credentials": "0100000000000000000000000000000000000000000000000000000000000001",
      "amount": 32000000000,
      "signature": "a1f3ece1cb871e1af29fdaf94cab58d48d128d0ed2342a1f042f49344943c25ec6eab4f2219301e421a88453c6aa29e90b78373a8341c17738bc0ff4d0a724494535b494cd21fd2633a7a12353a5232c9806e1576f1e2447631ec3310db4008b",
      "deposit_message_root": "dc224ac1c94d70906d643644f20398bdea5dabea123116a9d6135b8f5f4906bd",
      "deposit_data_root": "f5c6b52d2ba608f0df4123e5ed051b5765a636e09d1372668e1ec074430f2279",
      "fork_version": "00000000",
      "network_name": "mainnet",
      "deposit_cli_version": "2.3.0"
    }
  ]"#;
        // existing-mnemonic is deterministic, therefore both exports should be as expected
        for export in exports {
            // Asserts are for parts of string, cause keystore has different salt all the time.
            assert!(export.contains(expect_pks));
            assert!(export.contains(expect_mnemonic));
            assert!(export.contains(expect_deposit_data));
        }
    }

    #[test]
    fn test_export_validators_new_mnemonic() {
        fn validators_new_mnemonic() -> Validators<'static> {
            Validators::new(None, "test".as_bytes(), Some(1), false)
        }

        let exports: Vec<ValidatorExports> = vec![
            serde_json::from_str(
                &validators_new_mnemonic()
                    .export(
                        "mainnet".to_string(),
                        Some("0100000000000000000000000000000000000000000000000000000000000001"),
                        32_000_000_000,
                        "2.3.0".to_string(),
                        None,
                    )
                    .unwrap(),
            )
            .unwrap(),
            serde_json::from_str(
                &validators_new_mnemonic()
                    .export(
                        "mainnet".to_string(),
                        Some("0100000000000000000000000000000000000000000000000000000000000001"),
                        32_000_000_000,
                        "2.3.0".to_string(),
                        None,
                    )
                    .unwrap(),
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
        let validators = Validators::new(Some(PHRASE.as_bytes()), "test".as_bytes(), Some(1), true);

        let export = validators
            .export(
                "mainnet".to_string(),
                None,
                32_000_000_000,
                "2.3.0".to_string(),
                None,
            )
            .unwrap();

        let expect_deposit_data = r#""deposit_data": [
    {
      "pubkey": "8666389c3fe6ff0bca9adba81504f380b9e2c719419760d561836472fafe295cb50696524e19cba084e1d788d66c80d6",
      "withdrawal_credentials": "00e078f11bc1454244bdf9f63a3b997815f081dd6630204186d4c9627a2942f7",
      "amount": 32000000000,
      "signature": "8fb5a76232cb613c30e02b5946d252d0cc5ed8cfa81b7a1f781dc4f228c5e89e77b5b745fba4371be8ea7f02f6b7e18e0e3661b04a63d51197bd43b9dea27fef97b8e2b94ffc989fc29484537bfed9f99b6bc57b45c2004dd23e1502006640d4",
      "deposit_message_root": "9720268f705275b44bf4a7cd35246277f408dd245aafc676a3c335f1d714e724",
      "deposit_data_root": "270169ee3da4da7566daa4a29727b893bb1c6ce2f26b6c861afe6d480b3f9a7d",
      "fork_version": "00000000",
      "network_name": "mainnet",
      "deposit_cli_version": "2.3.0"
    }
  ]"#;

        println!("export: {}", export);

        export.contains(expect_deposit_data);
    }
}
