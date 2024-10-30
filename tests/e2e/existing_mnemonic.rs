use crate::e2e::DepositDataJson;
use assert_cmd::prelude::*;
use eth2_keystore::{
    json_keystore::{Crypto, JsonKeystore},
    Keystore,
};
use eth_staking_smith::ValidatorExports;
use predicates::prelude::*;
use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
};

/*
    set the MNEMONIC environment variable
    generate 1 validator without specifying the mnemonic
    (without withdrawal address specified, i.e. the address is derived from the public key)
    (without kdf specified, i.e. pbkdf2 will be used)

    This test is marked is sequential, because it modifies MNEMONIC
    environment variable state, which can interfere with the rest of the e2e tests.
*/
#[test]
#[serial_test::serial]
fn test_deposit_data_keystore_mnemonic_as_env_var() -> Result<(), Box<dyn std::error::Error>> {
    let chain = "goerli";
    let expected_decryption_password = "testtest";
    let expected_mnemonic = "ski interest capable knee usual ugly duty exercise tattoo subway delay upper bid forget say";
    std::env::set_var("MNEMONIC", expected_mnemonic);
    let num_validators = "1";

    // test directory
    let test_dir = get_test_dir("withdrawal_credentials_bls");

    // read expected files
    let expected_keystore_json =
        read_keystore_json(&test_dir, "keystore-m_12381_3600_0_0_0-1668613231.json");
    let expected_deposit_data = read_deposit_data_json(&test_dir, "deposit_data-1668613231.json");
    let expected_deposit_data_json = expected_deposit_data.get(0).unwrap();

    // decrypt keystore with expected password to derive private key
    let expected_private_key = decrypt_expected_keystore_file(
        expected_decryption_password,
        &expected_keystore_json.crypto,
    );

    // run eth-staking-smith

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("existing-mnemonic");
    cmd.arg("--chain");
    cmd.arg(chain);
    cmd.arg("--keystore_password");
    cmd.arg(expected_decryption_password);
    cmd.arg("--num_validators");
    cmd.arg(num_validators);

    cmd.assert().success();

    // read generated output

    let output = &cmd.output()?.stdout;
    let command_output = std::str::from_utf8(output)?;
    let generated_validator_json: ValidatorExports = serde_json::from_str(command_output)?;
    let generated_private_key = generated_validator_json
        .private_keys
        .get(0)
        .expect("could not get generated private key");
    let generated_deposit_data = generated_validator_json
        .deposit_data
        .get(0)
        .expect("could not get generated deposit data key");
    let keystore = generated_validator_json.keystores.get(0).unwrap();

    // compare private keys

    assert_eq!(expected_private_key, generated_private_key.to_owned());

    // compare deposit data

    assert_eq!(
        expected_deposit_data_json.pubkey.to_string(),
        generated_deposit_data.pubkey
    );
    assert_eq!(
        expected_deposit_data_json
            .withdrawal_credentials
            .to_string(),
        generated_deposit_data.withdrawal_credentials
    );
    assert_eq!(
        expected_deposit_data_json.amount.to_string(),
        generated_deposit_data.amount.to_string()
    );
    assert_eq!(
        expected_deposit_data_json.signature.to_string(),
        generated_deposit_data.signature.to_string()
    );

    // check that pbkdf2 was used if nothing else is specified
    assert_eq!("pbkdf2", parse_kdf_function(keystore));

    std::env::remove_var("MNEMONIC");

    Ok(())
}

/*
    generate 3 validators
*/
#[test]
fn test_multliple_validators() -> Result<(), Box<dyn std::error::Error>> {
    let chain = "goerli";
    let expected_decryption_password = "blablatest";
    let expected_mnemonic = "window lottery throw arrange visit play gate open scare strategy sadness fame soul bronze soap";
    let num_validators = "3";
    let execution_withdrawal_credentials = "0x0000000000000000000000000000000000000001";

    // test directory
    let test_dir = get_test_dir("multiple_validators");

    // read expected files
    let expected_deposit_data_json =
        read_deposit_data_json(&test_dir, "deposit_data-1670231001.json");

    let mut expected_keystore_jsons = vec![];
    let mut index = 0;

    for entry in std::fs::read_dir(&test_dir)? {
        let filename = entry?
            .file_name()
            .to_str()
            .expect("could not read filename")
            .to_owned();
        if filename.starts_with(&format!("keystore-m_12381_3600_{}", index)) {
            let keystore_path = test_dir.join(PathBuf::from_str(&filename)?);
            let keystore_file = std::fs::read_to_string(test_dir.join(keystore_path))?;
            let expected_keystore_json = serde_json::from_str::<JsonKeystore>(&keystore_file)?;
            expected_keystore_jsons.push(expected_keystore_json);
            index = index + 1;
        }
    }

    // run eth-staking-smith

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("existing-mnemonic");
    cmd.arg("--chain");
    cmd.arg(chain);
    cmd.arg("--keystore_password");
    cmd.arg(expected_decryption_password);
    cmd.arg("--mnemonic");
    cmd.arg(expected_mnemonic);
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
    let generated_private_keys = generated_validator_json.private_keys;
    let generated_deposit_data = generated_validator_json.deposit_data;

    // decrypt keystore with expected password to derive private key and compare private keys
    for index in 0..expected_keystore_jsons.len() {
        let expected_private_key_txt = eth2_keystore::decrypt(
            expected_decryption_password.as_bytes(),
            &expected_keystore_jsons[index].crypto,
        )
        .expect("could not decrypt keystore");
        let expected_private_key = hex::encode(expected_private_key_txt.as_bytes());
        assert_eq!(
            expected_private_key,
            generated_private_keys[index].to_owned()
        );
    }

    // compare deposit data entries
    for index in 0..expected_deposit_data_json.len() {
        let expected_deposit_data_json = &expected_deposit_data_json[index];

        assert_eq!(
            expected_deposit_data_json.pubkey.to_string(),
            generated_deposit_data[index].pubkey
        );
        assert_eq!(
            expected_deposit_data_json
                .withdrawal_credentials
                .to_string(),
            generated_deposit_data[index].withdrawal_credentials
        );
        assert_eq!(
            expected_deposit_data_json.amount.to_string(),
            generated_deposit_data[index].amount.to_string()
        );
        assert_eq!(
            expected_deposit_data_json.signature.to_string(),
            generated_deposit_data[index].signature.to_string()
        );
    }

    Ok(())
}

/*
    generate 1 validator overwriting withdrawal credentials with eth1 address
*/
#[test]
fn test_withdrawal_address_execution() -> Result<(), Box<dyn std::error::Error>> {
    let chain = "goerli";
    let expected_decryption_password = "anothertest";
    let expected_mnemonic = "satisfy suit expire castle fluid must electric genuine aim clock such under basic rabbit method";
    let num_validators = "1";
    let execution_withdrawal_credentials = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F";

    // test directory
    let test_dir = get_test_dir("withdrawal_credentials_execution");

    // read expected files
    let expected_keystore_json =
        read_keystore_json(&test_dir, "keystore-m_12381_3600_0_0_0-1669709160.json");
    let expected_deposit_data = read_deposit_data_json(&test_dir, "deposit_data-1669709160.json");
    let expected_deposit_data_json = expected_deposit_data.get(0).unwrap();

    // decrypt keystore with expected password to derive private key
    let expected_private_key = decrypt_expected_keystore_file(
        expected_decryption_password,
        &expected_keystore_json.crypto,
    );

    // run eth-staking-smith

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("existing-mnemonic");
    cmd.arg("--chain");
    cmd.arg(chain);
    cmd.arg("--keystore_password");
    cmd.arg(expected_decryption_password);
    cmd.arg("--mnemonic");
    cmd.arg(expected_mnemonic);
    cmd.arg("--num_validators");
    cmd.arg(num_validators);
    cmd.arg("--withdrawal_credentials");
    cmd.arg(execution_withdrawal_credentials);

    cmd.assert().success();

    // read generated output

    let output = &cmd.output()?.stdout;
    let command_output = std::str::from_utf8(output)?;
    let generated_validator_json: ValidatorExports = serde_json::from_str(command_output)?;
    let generated_private_key = generated_validator_json
        .private_keys
        .get(0)
        .expect("could not get generated private key");
    let generated_deposit_data = generated_validator_json
        .deposit_data
        .get(0)
        .expect("could not get generated deposit data");

    // compare private keys

    assert_eq!(expected_private_key, generated_private_key.to_owned());

    // compare deposit data

    assert_eq!(
        expected_deposit_data_json.pubkey.to_string(),
        generated_deposit_data.pubkey
    );
    assert_eq!(
        expected_deposit_data_json
            .withdrawal_credentials
            .to_string(),
        generated_deposit_data.withdrawal_credentials
    );
    assert_eq!(
        expected_deposit_data_json.amount.to_string(),
        generated_deposit_data.amount.to_string()
    );
    assert_eq!(
        expected_deposit_data_json.signature.to_string(),
        generated_deposit_data.signature.to_string()
    );

    Ok(())
}

/*
    generate 1 validator by passing in an existing bls credentials
    (to ensure correctness, we'll use the validator from testcase 1)
*/
#[test]
fn test_withdrawal_credentials_bls() -> Result<(), Box<dyn std::error::Error>> {
    let chain = "goerli";
    let expected_decryption_password = "testtest";
    let expected_mnemonic = "ski interest capable knee usual ugly duty exercise tattoo subway delay upper bid forget say";
    let num_validators = "1";
    let bls_withdrawal_credentials =
        "0x0045b91b2f60b88e7392d49ae1364b55e713d06f30e563f9f99e10994b26221d";

    // test directory
    let test_dir = get_test_dir("withdrawal_credentials_bls");

    // read expected files
    let expected_keystore_json =
        read_keystore_json(&test_dir, "keystore-m_12381_3600_0_0_0-1668613231.json");
    let expected_deposit_data = read_deposit_data_json(&test_dir, "deposit_data-1668613231.json");
    let expected_deposit_data_json = expected_deposit_data.get(0).unwrap();

    // decrypt keystore with expected password to derive private key
    let expected_private_key = decrypt_expected_keystore_file(
        expected_decryption_password,
        &expected_keystore_json.crypto,
    );

    // run eth-staking-smith

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("existing-mnemonic");
    cmd.arg("--chain");
    cmd.arg(chain);
    cmd.arg("--keystore_password");
    cmd.arg(expected_decryption_password);
    cmd.arg("--mnemonic");
    cmd.arg(expected_mnemonic);
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
        .expect("could not get generated deposit data");

    // compare private keys

    assert_eq!(expected_private_key, generated_private_key.to_owned());

    // compare deposit data

    assert_eq!(
        expected_deposit_data_json.pubkey.to_string(),
        generated_deposit_data.pubkey
    );
    assert_eq!(
        expected_deposit_data_json
            .withdrawal_credentials
            .to_string(),
        generated_deposit_data.withdrawal_credentials
    );
    assert_eq!(
        expected_deposit_data_json.amount.to_string(),
        generated_deposit_data.amount.to_string()
    );
    assert_eq!(
        expected_deposit_data_json.signature.to_string(),
        generated_deposit_data.signature.to_string()
    );

    Ok(())
}

/*
    generate 1 validator overwriting withdrawal credentials with eth1 credentials
    (to ensure correctness, we'll use the validator from testcase withdrawal_credentials_execution)
*/
#[test]
fn test_withdrawal_credentials_execution() -> Result<(), Box<dyn std::error::Error>> {
    let chain = "goerli";
    let expected_decryption_password = "anothertest";
    let expected_mnemonic = "satisfy suit expire castle fluid must electric genuine aim clock such under basic rabbit method";
    let num_validators = "1";
    let execution_withdrawal_credentials =
        "0x01000000000000000000000071c7656ec7ab88b098defb751b7401b5f6d8976f";

    // test directory
    let test_dir = get_test_dir("withdrawal_credentials_execution");

    // read expected files
    let expected_keystore_json =
        read_keystore_json(&test_dir, "keystore-m_12381_3600_0_0_0-1669709160.json");
    let expected_deposit_data = read_deposit_data_json(&test_dir, "deposit_data-1669709160.json");
    let expected_deposit_data_json = expected_deposit_data.get(0).unwrap();

    // decrypt keystore with expected password to derive private key
    let expected_private_key = decrypt_expected_keystore_file(
        expected_decryption_password,
        &expected_keystore_json.crypto,
    );

    // run eth-staking-smith

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("existing-mnemonic");
    cmd.arg("--chain");
    cmd.arg(chain);
    cmd.arg("--keystore_password");
    cmd.arg(expected_decryption_password);
    cmd.arg("--mnemonic");
    cmd.arg(expected_mnemonic);
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
    let generated_private_key = generated_validator_json
        .private_keys
        .get(0)
        .expect("could not get generated private key");
    let generated_deposit_data = generated_validator_json
        .deposit_data
        .get(0)
        .expect("could not get generated deposit data");

    // compare private keys

    assert_eq!(expected_private_key, generated_private_key.to_owned());

    // compare deposit data

    assert_eq!(
        expected_deposit_data_json.pubkey.to_string(),
        generated_deposit_data.pubkey
    );
    assert_eq!(
        expected_deposit_data_json
            .withdrawal_credentials
            .to_string(),
        generated_deposit_data.withdrawal_credentials
    );
    assert_eq!(
        expected_deposit_data_json.amount.to_string(),
        generated_deposit_data.amount.to_string()
    );
    assert_eq!(
        expected_deposit_data_json.signature.to_string(),
        generated_deposit_data.signature.to_string()
    );

    Ok(())
}

/*
    generate 1 validator with pdf pbkdf2 specified
*/
#[test]
fn test_keystore_kdf_pbkdf2() -> Result<(), Box<dyn std::error::Error>> {
    let chain = "goerli";
    let expected_decryption_password = "testtest";
    let expected_mnemonic = "ski interest capable knee usual ugly duty exercise tattoo subway delay upper bid forget say";
    let num_validators = "1";
    let kdf = "pbkdf2";

    // test directory
    let test_dir = get_test_dir("withdrawal_credentials_bls");

    // read expected files
    let expected_keystore_json =
        read_keystore_json(&test_dir, "keystore-m_12381_3600_0_0_0-1668613231.json");
    let expected_deposit_data = read_deposit_data_json(&test_dir, "deposit_data-1668613231.json");
    let expected_deposit_data_json = expected_deposit_data.get(0).unwrap();

    // decrypt keystore with expected password to derive private key
    let expected_private_key = decrypt_expected_keystore_file(
        expected_decryption_password,
        &expected_keystore_json.crypto,
    );

    // run eth-staking-smith

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("existing-mnemonic");
    cmd.arg("--chain");
    cmd.arg(chain);
    cmd.arg("--keystore_password");
    cmd.arg(expected_decryption_password);
    cmd.arg("--mnemonic");
    cmd.arg(expected_mnemonic);
    cmd.arg("--num_validators");
    cmd.arg(num_validators);
    cmd.arg("--kdf");
    cmd.arg(kdf);

    cmd.assert().success();

    // read generated output

    let output = &cmd.output()?.stdout;
    let command_output = std::str::from_utf8(output)?;
    let generated_validator_json: ValidatorExports = serde_json::from_str(command_output)?;
    let generated_private_key = generated_validator_json
        .private_keys
        .get(0)
        .expect("could not get generated private key");
    let generated_deposit_data = generated_validator_json
        .deposit_data
        .get(0)
        .expect("could not get generated deposit data key");
    let keystore = generated_validator_json.keystores.get(0).unwrap();

    // compare private keys

    assert_eq!(expected_private_key, generated_private_key.to_owned());

    // compare deposit data

    assert_eq!(
        expected_deposit_data_json.pubkey.to_string(),
        generated_deposit_data.pubkey
    );
    assert_eq!(
        expected_deposit_data_json
            .withdrawal_credentials
            .to_string(),
        generated_deposit_data.withdrawal_credentials
    );
    assert_eq!(
        expected_deposit_data_json.amount.to_string(),
        generated_deposit_data.amount.to_string()
    );
    assert_eq!(
        expected_deposit_data_json.signature.to_string(),
        generated_deposit_data.signature.to_string()
    );

    // check that specified kdf was used
    assert_eq!("pbkdf2", parse_kdf_function(keystore));

    Ok(())
}

/*
    generate 1 validator with new mnemonic and kdf scrypt specified
*/
#[test]
fn test_keystore_kdf_scrypt() -> Result<(), Box<dyn std::error::Error>> {
    let chain = "goerli";
    let expected_decryption_password = "testtest";
    let expected_mnemonic = "ski interest capable knee usual ugly duty exercise tattoo subway delay upper bid forget say";
    let num_validators = "1";
    let kdf = "scrypt";

    // test directory
    let test_dir = get_test_dir("withdrawal_credentials_bls");

    // read expected files
    let expected_keystore_json =
        read_keystore_json(&test_dir, "keystore-m_12381_3600_0_0_0-1668613231.json");
    let expected_deposit_data = read_deposit_data_json(&test_dir, "deposit_data-1668613231.json");
    let expected_deposit_data_json = expected_deposit_data.get(0).unwrap();

    // decrypt keystore with expected password to derive private key
    let expected_private_key = decrypt_expected_keystore_file(
        expected_decryption_password,
        &expected_keystore_json.crypto,
    );

    // run eth-staking-smith

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("existing-mnemonic");
    cmd.arg("--chain");
    cmd.arg(chain);
    cmd.arg("--keystore_password");
    cmd.arg(expected_decryption_password);
    cmd.arg("--mnemonic");
    cmd.arg(expected_mnemonic);
    cmd.arg("--num_validators");
    cmd.arg(num_validators);
    cmd.arg("--kdf");
    cmd.arg(kdf);

    cmd.assert().success();

    // read generated output

    let output = &cmd.output()?.stdout;
    let command_output = std::str::from_utf8(output)?;
    let generated_validator_json: ValidatorExports = serde_json::from_str(command_output)?;
    let generated_private_key = generated_validator_json
        .private_keys
        .get(0)
        .expect("could not get generated private key");
    let generated_deposit_data = generated_validator_json
        .deposit_data
        .get(0)
        .expect("could not get generated deposit data key");
    let keystore = generated_validator_json.keystores.get(0).unwrap();

    // compare private keys

    assert_eq!(expected_private_key, generated_private_key.to_owned());

    // compare deposit data

    assert_eq!(
        expected_deposit_data_json.pubkey.to_string(),
        generated_deposit_data.pubkey
    );
    assert_eq!(
        expected_deposit_data_json
            .withdrawal_credentials
            .to_string(),
        generated_deposit_data.withdrawal_credentials
    );
    assert_eq!(
        expected_deposit_data_json.amount.to_string(),
        generated_deposit_data.amount.to_string()
    );
    assert_eq!(
        expected_deposit_data_json.signature.to_string(),
        generated_deposit_data.signature.to_string()
    );

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
    let expected_mnemonic = "satisfy suit expire castle fluid must electric genuine aim clock such under basic rabbit method";
    let num_validators = "1";
    let execution_withdrawal_credentials =
        "0x01000000000000000000000071c7656ec7ab88b098defb751b7401b5f6d8976f";

    // run eth-staking-smith

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("existing-mnemonic");
    cmd.arg("--chain");
    cmd.arg(chain);
    cmd.arg("--mnemonic");
    cmd.arg(expected_mnemonic);
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
    custom testnet config
*/
#[test]
fn test_existing_custom_testnet_config() -> Result<(), Box<dyn std::error::Error>> {
    let mut manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.push("tests/resources/minimal.yaml");
    let testnet_config = manifest.to_str().unwrap();
    let expected_mnemonic = "satisfy suit expire castle fluid must electric genuine aim clock such under basic rabbit method";
    let num_validators = "1";
    let execution_withdrawal_credentials =
        "0x01000000000000000000000071c7656ec7ab88b098defb751b7401b5f6d8976f";

    // run eth-staking-smith

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("existing-mnemonic");
    cmd.arg("--testnet_config");
    cmd.arg(testnet_config);
    cmd.arg("--mnemonic");
    cmd.arg(expected_mnemonic);
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

    let generated_private_key = generated_validator_json
        .private_keys
        .first()
        .unwrap()
        .clone();
    let first_deposit_item = generated_validator_json.deposit_data.first().unwrap();
    let generated_fork_version = first_deposit_item.fork_version.clone();
    assert_eq!(
        generated_private_key,
        "65bee7f836609f83f2fac858208595c97eb69732ac66317d638713651dd7572a"
    );
    assert_eq!(generated_fork_version, "00000001");
    Ok(())
}

/*
    attempt to generate validator with wrong mnemonic format
*/
#[test]
fn test_error_phrase_too_short() -> Result<(), Box<dyn std::error::Error>> {
    let chain = "goerli";
    let expected_decryption_password = "testtest";
    let mnemonic_not_enough_words = "bid forget say";
    let num_validators = "1";

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("existing-mnemonic");
    cmd.arg("--chain");
    cmd.arg(chain);
    cmd.arg("--keystore_password");
    cmd.arg(expected_decryption_password);
    cmd.arg("--mnemonic");
    cmd.arg(mnemonic_not_enough_words);
    cmd.arg("--num_validators");
    cmd.arg(num_validators);

    cmd.assert().failure().stderr(predicate::str::contains(
        "Invalid phrase passed: invalid number of words in phrase: 3",
    ));

    Ok(())
}

/*
    attempt to generate validator with unsupported network
*/
#[test]
fn test_error_unsupported_network() -> Result<(), Box<dyn std::error::Error>> {
    let unsupported_network = "goerliX";
    let expected_decryption_password = "testtest";
    let expected_mnemonic = "satisfy suit expire castle fluid must electric genuine aim clock such under basic rabbit method";
    let num_validators = "1";

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("existing-mnemonic");
    cmd.arg("--chain");
    cmd.arg(unsupported_network);
    cmd.arg("--keystore_password");
    cmd.arg(expected_decryption_password);
    cmd.arg("--mnemonic");
    cmd.arg(expected_mnemonic);
    cmd.arg("--num_validators");
    cmd.arg(num_validators);

    cmd.assert().failure().stderr(predicate::str::contains(
        "invalid value \'goerliX\' for \'--chain <CHAIN>\'",
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
    let expected_mnemonic = "satisfy suit expire castle fluid must electric genuine aim clock such under basic rabbit method";
    let num_validators = "1";
    let unsupported_kdf = "pbkdf3";

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("existing-mnemonic");
    cmd.arg("--chain");
    cmd.arg(network);
    cmd.arg("--keystore_password");
    cmd.arg(expected_decryption_password);
    cmd.arg("--mnemonic");
    cmd.arg(expected_mnemonic);
    cmd.arg("--num_validators");
    cmd.arg(num_validators);
    cmd.arg("--kdf");
    cmd.arg(unsupported_kdf);

    cmd.assert().failure().stderr(predicate::str::contains(
        "invalid value 'pbkdf3' for '--kdf <KDF>'",
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
    let expected_mnemonic = "satisfy suit expire castle fluid must electric genuine aim clock such under basic rabbit method";
    let num_validators = "1";

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("existing-mnemonic");
    cmd.arg("--chain");
    cmd.arg(chain);
    cmd.arg("--keystore_password");
    cmd.arg(decryption_password_too_short);
    cmd.arg("--mnemonic");
    cmd.arg(expected_mnemonic);
    cmd.arg("--num_validators");
    cmd.arg(num_validators);

    cmd.assert().failure().stderr(predicate::str::contains(
        "The password length should be at least 8",
    ));

    Ok(())
}

fn get_test_dir(testcase: &str) -> PathBuf {
    let cwd = env::current_dir().expect("could not get current directory");
    let test_path = cwd.join(Path::new(&format!(
        "tests/e2e/expected_testdata/{}",
        testcase
    )));
    test_path
}

/*
    We use the same mnemonic as in testcase multiple validators, but regenerate from the second key
*/
#[test]
fn test_regenerate_from_seed_index() -> Result<(), Box<dyn std::error::Error>> {
    let chain = "goerli";
    let expected_decryption_password = "blablatest";
    let expected_mnemonic = "window lottery throw arrange visit play gate open scare strategy sadness fame soul bronze soap";
    let num_validators = "2";
    let validator_start_index = "1";
    let execution_withdrawal_credentials = "0x0000000000000000000000000000000000000001";

    // test directory
    let test_dir = get_test_dir("regenerate_from_seed_index");

    // read expected files
    let expected_deposit_data_json =
        read_deposit_data_json(&test_dir, "deposit_data-1670927040.json");

    let mut expected_keystore_jsons = vec![];
    let mut index = 0;

    for entry in std::fs::read_dir(&test_dir)? {
        let filename = entry?
            .file_name()
            .to_str()
            .expect("could not read filename")
            .to_owned();
        if filename.starts_with(&format!("keystore-m_12381_3600_{}", index)) {
            let keystore_path = test_dir.join(PathBuf::from_str(&filename)?);
            let keystore_file = std::fs::read_to_string(test_dir.join(keystore_path))?;
            let expected_keystore_json = serde_json::from_str::<JsonKeystore>(&keystore_file)?;
            expected_keystore_jsons.push(expected_keystore_json);
            index = index + 1;
        }
    }

    // run eth-staking-smith

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("existing-mnemonic");
    cmd.arg("--chain");
    cmd.arg(chain);
    cmd.arg("--keystore_password");
    cmd.arg(expected_decryption_password);
    cmd.arg("--mnemonic");
    cmd.arg(expected_mnemonic);
    cmd.arg("--num_validators");
    cmd.arg(num_validators);
    cmd.arg("--validator_start_index");
    cmd.arg(validator_start_index);
    cmd.arg("--withdrawal_credentials");
    cmd.arg(execution_withdrawal_credentials);

    cmd.assert().success();

    // read generated output

    let output = &cmd.output()?.stdout;
    let command_output = std::str::from_utf8(output)?;
    let generated_validator_json: ValidatorExports =
        serde_json::from_str(command_output).expect("could not unmarshal command output");
    let generated_private_keys = generated_validator_json.private_keys;
    let generated_deposit_data = generated_validator_json.deposit_data;

    // decrypt keystore with expected password to derive private key and compare private keys
    for index in 0..expected_keystore_jsons.len() {
        let expected_private_key_txt = eth2_keystore::decrypt(
            expected_decryption_password.as_bytes(),
            &expected_keystore_jsons[index].crypto,
        )
        .expect("could not decrypt keystore");
        let expected_private_key = hex::encode(expected_private_key_txt.as_bytes());
        assert_eq!(
            expected_private_key,
            generated_private_keys[index].to_owned()
        );
    }

    // compare deposit data entries
    for index in 0..expected_deposit_data_json.len() {
        let expected_deposit_data_json = &expected_deposit_data_json[index];

        assert_eq!(
            expected_deposit_data_json.pubkey.to_string(),
            generated_deposit_data[index].pubkey
        );
        assert_eq!(
            expected_deposit_data_json
                .withdrawal_credentials
                .to_string(),
            generated_deposit_data[index].withdrawal_credentials
        );
        assert_eq!(
            expected_deposit_data_json.amount.to_string(),
            generated_deposit_data[index].amount.to_string()
        );
        assert_eq!(
            expected_deposit_data_json.signature.to_string(),
            generated_deposit_data[index].signature.to_string()
        );
    }

    Ok(())
}

fn read_keystore_json(test_path: &PathBuf, keystore_filename: &str) -> JsonKeystore {
    let keystore_path = test_path.join(Path::new(&keystore_filename));
    let keystore_file =
        std::fs::read_to_string(keystore_path).expect("could not read keystore from path");
    let expected_keystore_json = serde_json::from_str::<JsonKeystore>(&keystore_file)
        .expect("could not unmarshal keystore json");
    expected_keystore_json
}

fn decrypt_expected_keystore_file(
    expected_decryption_password: &str,
    expected_keystore_crypto: &Crypto,
) -> String {
    let expected_private_key_txt = eth2_keystore::decrypt(
        expected_decryption_password.as_bytes(),
        &expected_keystore_crypto,
    )
    .expect("could not decrypt keystore");
    let expected_private_key = hex::encode(expected_private_key_txt.as_bytes());
    expected_private_key
}

fn read_deposit_data_json(
    test_path: &PathBuf,
    deposit_data_filename: &str,
) -> Vec<DepositDataJson> {
    let deposit_data_path = test_path.join(Path::new(deposit_data_filename));
    let deposit_data_file =
        std::fs::read_to_string(deposit_data_path).expect("could not read deposit data");
    serde_json::from_str::<Vec<DepositDataJson>>(&deposit_data_file)
        .expect("could not unmarshal deposit data json")
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
