use assert_cmd::prelude::*;
use eth2_keystore::{json_keystore::JsonKeystore, Keystore};
use eth_staking_smith::ValidatorExports;
use predicates::prelude::*;
use std::{path::PathBuf, process::Command};

/*
    generate 1 validator with new mnemonic
    (without withdrawal address specified, i.e. the address is derived from the public key)
    (without kdf specified, i.e. pbkdf2 will be used)
*/
#[test]
fn test_deposit_data_keystore() -> Result<(), Box<dyn std::error::Error>> {
    let chain = "goerli";
    let decryption_password = "testtest";
    let num_validators = "1";

    // run eth-staking-smith

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("new-mnemonic");
    cmd.arg("--chain");
    cmd.arg(chain);
    cmd.arg("--keystore_password");
    cmd.arg(decryption_password);
    cmd.arg("--num_validators");
    cmd.arg(num_validators);

    cmd.assert().success();

    // read generated output

    let output = &cmd
        .output()
        .expect("could not get output from command")
        .stdout;
    let command_output = std::str::from_utf8(output).expect("could not parse output into string");
    let generated_validator_json: ValidatorExports =
        serde_json::from_str(command_output).expect("could not unmarshal command output");
    let generated_private_key = generated_validator_json
        .private_keys
        .get(0)
        .expect("could not get generated private key");
    let generated_deposit_data = generated_validator_json
        .deposit_data
        .get(0)
        .expect("could not get generated private key")
        .to_owned();
    let keystore = generated_validator_json.keystores.get(0).unwrap();

    generated_deposit_data.validate(
        eth_staking_smith::chain_spec::chain_spec_for_network(chain.to_string()).unwrap(),
    );

    // decrypt keystore with expected password to derive private key
    let encoded_private_key = decrypt_generated_keystore(
        generated_validator_json.keystores.get(0).unwrap(),
        decryption_password,
    );
    assert_eq!(generated_private_key, &encoded_private_key);

    // check pbkdf2 was used if nothing else is specified
    assert_eq!("pbkdf2", parse_kdf_function(keystore));

    Ok(())
}

/*
    generate 3 validators
*/
#[test]
fn test_multliple_validators() -> Result<(), Box<dyn std::error::Error>> {
    let chain = "goerli";
    let decryption_password = "testtest";
    let num_validators = "3";
    let execution_withdrawal_credentials = "0x0000000000000000000000000000000000000001";

    // run eth-staking-smith

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("new-mnemonic");
    cmd.arg("--chain");
    cmd.arg(chain);
    cmd.arg("--keystore_password");
    cmd.arg(decryption_password);
    cmd.arg("--num_validators");
    cmd.arg(num_validators);
    cmd.arg("--withdrawal_credentials");
    cmd.arg(execution_withdrawal_credentials);

    cmd.assert().success();

    // read generated output

    let output = &cmd
        .output()
        .expect("could not get output from command")
        .stdout;
    let command_output = std::str::from_utf8(output).expect("could not parse output into string");
    let generated_validator_json: ValidatorExports =
        serde_json::from_str(command_output).expect("could not unmarshal command output");
    let generated_private_keys = generated_validator_json.private_keys;
    let generated_deposit_datas = generated_validator_json.deposit_data;

    let spec = eth_staking_smith::chain_spec::chain_spec_for_network("goerli".to_string()).unwrap();

    for deposit_data in generated_deposit_datas {
        deposit_data.validate(spec.clone());
    }

    for index in 0..generated_private_keys.len() {
        // decrypt keystore with expected password to derive private key
        let encoded_private_key = decrypt_generated_keystore(
            generated_validator_json
                .keystores
                .get(index)
                .expect("could not get keystore"),
            decryption_password,
        );
        assert_eq!(
            generated_private_keys
                .get(index)
                .expect("could not get private keys"),
            &encoded_private_key
        );
    }

    Ok(())
}

/*
    generate 1 validator overwriting withdrawal credentials with execution address
*/
#[test]
fn test_withdrawal_address_execution() -> Result<(), Box<dyn std::error::Error>> {
    let chain = "goerli";
    let decryption_password = "testtest";
    let num_validators = "1";
    let execution_withdrawal_credentials = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F";

    // run eth-staking-smith

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("new-mnemonic");
    cmd.arg("--chain");
    cmd.arg(chain);
    cmd.arg("--keystore_password");
    cmd.arg(decryption_password);
    cmd.arg("--num_validators");
    cmd.arg(num_validators);
    cmd.arg("--withdrawal_credentials");
    cmd.arg(execution_withdrawal_credentials);

    cmd.assert().success();

    // read generated output

    let output = &cmd
        .output()
        .expect("could not get output from command")
        .stdout;
    let command_output = std::str::from_utf8(output).expect("could not parse output into string");
    let generated_validator_json: ValidatorExports =
        serde_json::from_str(command_output).expect("could not unmarshal command output");
    let generated_private_key = generated_validator_json
        .private_keys
        .get(0)
        .expect("could not get generated private key");
    let generated_deposit_data = generated_validator_json
        .deposit_data
        .get(0)
        .expect("could not get generated private key")
        .to_owned();

    generated_deposit_data.validate(
        eth_staking_smith::chain_spec::chain_spec_for_network(chain.to_string()).unwrap(),
    );

    // decrypt keystore with expected password to derive private key
    let encoded_private_key = decrypt_generated_keystore(
        generated_validator_json.keystores.get(0).unwrap(),
        decryption_password,
    );
    assert_eq!(generated_private_key, &encoded_private_key);

    Ok(())
}

/*
    generate 1 validator by passing in an existing bls credentials
*/
#[test]
fn test_withdrawal_credentials_bls() -> Result<(), Box<dyn std::error::Error>> {
    let chain = "goerli";
    let decryption_password = "testtest";
    let num_validators = "3";
    let bls_withdrawal_credentials =
        "0x0045b91b2f60b88e7392d49ae1364b55e713d06f30e563f9f99e10994b26221d";
    // run eth-staking-smith

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("new-mnemonic");
    cmd.arg("--chain");
    cmd.arg(chain);
    cmd.arg("--keystore_password");
    cmd.arg(decryption_password);
    cmd.arg("--num_validators");
    cmd.arg(num_validators);
    cmd.arg("--withdrawal_credentials");
    cmd.arg(bls_withdrawal_credentials);

    cmd.assert().success();

    // read generated output

    let output = &cmd
        .output()
        .expect("could not get output from command")
        .stdout;
    let command_output = std::str::from_utf8(output).expect("could not parse output into string");
    let generated_validator_json: ValidatorExports =
        serde_json::from_str(command_output).expect("could not unmarshal command output");
    let generated_private_key = generated_validator_json
        .private_keys
        .get(0)
        .expect("could not get generated private key");
    let generated_deposit_data = generated_validator_json
        .deposit_data
        .get(0)
        .expect("could not get generated private key")
        .to_owned();

    generated_deposit_data.validate(
        eth_staking_smith::chain_spec::chain_spec_for_network(chain.to_string()).unwrap(),
    );

    // decrypt keystore with expected password to derive private key
    let encoded_private_key = decrypt_generated_keystore(
        generated_validator_json.keystores.get(0).unwrap(),
        decryption_password,
    );
    assert_eq!(generated_private_key, &encoded_private_key);

    Ok(())
}

/*
    generate 1 validator overwriting withdrawal credentials with execution credentials
*/
#[test]
fn test_new_custom_testnet_config() -> Result<(), Box<dyn std::error::Error>> {
    let mut manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.push("tests/resources/minimal.yaml");
    let testnet_config = manifest.to_str().unwrap();
    let decryption_password = "testtest";
    let num_validators = "3";
    let execution_withdrawal_credentials =
        "0x01000000000000000000000071c7656ec7ab88b098defb751b7401b5f6d8976f";

    // run eth-staking-smith

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("new-mnemonic");
    cmd.arg("--testnet_config");
    cmd.arg(testnet_config);
    cmd.arg("--keystore_password");
    cmd.arg(decryption_password);
    cmd.arg("--num_validators");
    cmd.arg(num_validators);
    cmd.arg("--withdrawal_credentials");
    cmd.arg(execution_withdrawal_credentials);

    cmd.assert().success();

    // read generated output

    let output = &cmd
        .output()
        .expect("could not get output from command")
        .stdout;
    let command_output = std::str::from_utf8(output).expect("could not parse output into string");
    let generated_validator_json: ValidatorExports =
        serde_json::from_str(command_output).expect("could not unmarshal command output");
    let generated_private_key = generated_validator_json
        .private_keys
        .get(0)
        .expect("could not get generated private key");
    let generated_deposit_data = generated_validator_json
        .deposit_data
        .get(0)
        .expect("could not get generated deposit data")
        .to_owned();

    generated_deposit_data.validate(
        eth_staking_smith::chain_spec::chain_spec_from_file(testnet_config.to_string()).unwrap(),
    );

    // decrypt keystore with expected password to derive private key
    let encoded_private_key = decrypt_generated_keystore(
        generated_validator_json.keystores.get(0).unwrap(),
        decryption_password,
    );
    assert_eq!(generated_private_key, &encoded_private_key);

    Ok(())
}

/*
    generate 1 validator overwriting withdrawal credentials with execution credentials
*/
#[test]
fn test_withdrawal_credentials_execution() -> Result<(), Box<dyn std::error::Error>> {
    let chain = "goerli";
    let decryption_password = "testtest";
    let num_validators = "3";
    let execution_withdrawal_credentials =
        "0x01000000000000000000000071c7656ec7ab88b098defb751b7401b5f6d8976f";

    // run eth-staking-smith

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("new-mnemonic");
    cmd.arg("--chain");
    cmd.arg(chain);
    cmd.arg("--keystore_password");
    cmd.arg(decryption_password);
    cmd.arg("--num_validators");
    cmd.arg(num_validators);
    cmd.arg("--withdrawal_credentials");
    cmd.arg(execution_withdrawal_credentials);

    cmd.assert().success();

    // read generated output

    let output = &cmd
        .output()
        .expect("could not get output from command")
        .stdout;
    let command_output = std::str::from_utf8(output).expect("could not parse output into string");
    let generated_validator_json: ValidatorExports =
        serde_json::from_str(command_output).expect("could not unmarshal command output");
    let generated_private_key = generated_validator_json
        .private_keys
        .get(0)
        .expect("could not get generated private key");
    let generated_deposit_data = generated_validator_json
        .deposit_data
        .get(0)
        .expect("could not get generated deposit data")
        .to_owned();

    generated_deposit_data.validate(
        eth_staking_smith::chain_spec::chain_spec_for_network(chain.to_string()).unwrap(),
    );

    // decrypt keystore with expected password to derive private key
    let encoded_private_key = decrypt_generated_keystore(
        generated_validator_json.keystores.get(0).unwrap(),
        decryption_password,
    );
    assert_eq!(generated_private_key, &encoded_private_key);

    Ok(())
}

/*
    generate 1 validator with new mnemonic with kdf pbkdf2 specified
*/
#[test]
fn test_keystore_kdf_pbkdf2() -> Result<(), Box<dyn std::error::Error>> {
    let chain = "goerli";
    let decryption_password = "testtest";
    let num_validators = "1";
    let kdf = "pbkdf2";

    // run eth-staking-smith

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("new-mnemonic");
    cmd.arg("--chain");
    cmd.arg(chain);
    cmd.arg("--keystore_password");
    cmd.arg(decryption_password);
    cmd.arg("--num_validators");
    cmd.arg(num_validators);
    cmd.arg("--kdf");
    cmd.arg(kdf);

    cmd.assert().success();

    // read generated output

    let output = &cmd
        .output()
        .expect("could not get output from command")
        .stdout;
    let command_output = std::str::from_utf8(output).expect("could not parse output into string");
    let generated_validator_json: ValidatorExports =
        serde_json::from_str(command_output).expect("could not unmarshal command output");
    let generated_private_key = generated_validator_json
        .private_keys
        .get(0)
        .expect("could not get generated private key");
    let generated_deposit_data = generated_validator_json
        .deposit_data
        .get(0)
        .expect("could not get generated private key")
        .to_owned();
    let keystore = generated_validator_json.keystores.get(0).unwrap();

    generated_deposit_data.validate(
        eth_staking_smith::chain_spec::chain_spec_for_network(chain.to_string()).unwrap(),
    );

    // decrypt keystore with expected password to derive private key
    let encoded_private_key = decrypt_generated_keystore(
        generated_validator_json.keystores.get(0).unwrap(),
        decryption_password,
    );
    assert_eq!(generated_private_key, &encoded_private_key);

    // check that correct kdf was used
    assert_eq!("pbkdf2", parse_kdf_function(keystore));

    Ok(())
}

/*
    generate 1 validator with new mnemonic with kdf scrypt specified
*/
#[test]
fn test_keystore_kdf_scrypt() -> Result<(), Box<dyn std::error::Error>> {
    let chain = "goerli";
    let decryption_password = "testtest";
    let num_validators = "1";
    let kdf = "scrypt";

    // run eth-staking-smith

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("new-mnemonic");
    cmd.arg("--chain");
    cmd.arg(chain);
    cmd.arg("--keystore_password");
    cmd.arg(decryption_password);
    cmd.arg("--num_validators");
    cmd.arg(num_validators);
    cmd.arg("--kdf");
    cmd.arg(kdf);

    cmd.assert().success();

    // read generated output

    let output = &cmd
        .output()
        .expect("could not get output from command")
        .stdout;
    let command_output = std::str::from_utf8(output).expect("could not parse output into string");
    let generated_validator_json: ValidatorExports =
        serde_json::from_str(command_output).expect("could not unmarshal command output");
    let generated_private_key = generated_validator_json
        .private_keys
        .get(0)
        .expect("could not get generated private key");
    let generated_deposit_data = generated_validator_json
        .deposit_data
        .get(0)
        .expect("could not get generated private key")
        .to_owned();
    let keystore = generated_validator_json.keystores.get(0).unwrap();

    generated_deposit_data.validate(
        eth_staking_smith::chain_spec::chain_spec_for_network(chain.to_string()).unwrap(),
    );

    // decrypt keystore with expected password to derive private key
    let encoded_private_key = decrypt_generated_keystore(
        generated_validator_json.keystores.get(0).unwrap(),
        decryption_password,
    );
    assert_eq!(generated_private_key, &encoded_private_key);

    // check that correct kdf was used
    assert_eq!("scrypt", parse_kdf_function(keystore));

    Ok(())
}

/*
    omitting keystore password argument will not generate keystore files
*/
#[test]
fn test_omitting_keystore_password() -> Result<(), Box<dyn std::error::Error>> {
    let chain = "goerli";
    let num_validators = "1";
    let execution_withdrawal_credentials =
        "0x01000000000000000000000071c7656ec7ab88b098defb751b7401b5f6d8976f";

    // run eth-staking-smith

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("new-mnemonic");
    cmd.arg("--chain");
    cmd.arg(chain);
    cmd.arg("--num_validators");
    cmd.arg(num_validators);
    cmd.arg("--withdrawal_credentials");
    cmd.arg(execution_withdrawal_credentials);

    cmd.assert().success();

    // read generated output

    let output = &cmd.output()?.stdout;
    let command_output = std::str::from_utf8(output)?;
    let generated_validator_json: ValidatorExports =
        serde_json::from_str(command_output).expect("could not unmarshal command output");

    assert!(generated_validator_json.keystores.is_empty());

    Ok(())
}

/*
    attempt to generate validator with non-supported network
*/
#[test]
fn test_error_unsupported_network() -> Result<(), Box<dyn std::error::Error>> {
    let unsupported_network = "goerliX";
    let expected_decryption_password = "testtest";
    let num_validators = "1";

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("new-mnemonic");
    cmd.arg("--chain");
    cmd.arg(unsupported_network);
    cmd.arg("--keystore_password");
    cmd.arg(expected_decryption_password);
    cmd.arg("--num_validators");
    cmd.arg(num_validators);

    cmd.assert().failure().stderr(predicate::str::contains(
        "goerliX' isn't a valid value for '--chain <chain>",
    ));

    Ok(())
}

/*
    attempt to generate validator with unsupported kdf
*/
#[test]
fn test_error_unsupported_kdf() -> Result<(), Box<dyn std::error::Error>> {
    let network = "goerli";
    let expected_decryption_password = "testtest";
    let num_validators = "1";
    let unsupported_kdf = "pbkdf3";

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("new-mnemonic");
    cmd.arg("--chain");
    cmd.arg(network);
    cmd.arg("--keystore_password");
    cmd.arg(expected_decryption_password);
    cmd.arg("--num_validators");
    cmd.arg(num_validators);
    cmd.arg("--kdf");
    cmd.arg(unsupported_kdf);

    cmd.assert().failure().stderr(predicate::str::contains(
        "pbkdf3' isn't a valid value for '--kdf <kdf>",
    ));

    Ok(())
}

/*
    attempt to generate validator with decription too short
*/
#[test]
fn test_error_password_too_short() -> Result<(), Box<dyn std::error::Error>> {
    let chain = "goerli";
    let decryption_password_too_short = "t";
    let num_validators = "1";

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("new-mnemonic");
    cmd.arg("--chain");
    cmd.arg(chain);
    cmd.arg("--keystore_password");
    cmd.arg(decryption_password_too_short);
    cmd.arg("--num_validators");
    cmd.arg(num_validators);

    cmd.assert().failure().stderr(predicate::str::contains(
        "The password length should be at least 8",
    ));

    Ok(())
}

fn decrypt_generated_keystore(keystore: &Keystore, decryption_password: &str) -> String {
    let decrypted_private_key = keystore
        .decrypt_keypair(decryption_password.as_bytes())
        .unwrap()
        .sk
        .serialize();
    let encoded_private_key = hex::encode(&decrypted_private_key.as_bytes());
    encoded_private_key
}

fn parse_kdf_function(keystore: &Keystore) -> String {
    let keystore_json: JsonKeystore = serde_json::from_str(&keystore.to_json_string().unwrap())
        .expect("could not parse keystore json");
    let kdf_function: String = keystore_json
        .crypto
        .kdf
        .function
        .to_owned()
        .try_into()
        .unwrap();
    kdf_function
}
