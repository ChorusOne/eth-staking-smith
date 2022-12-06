use assert_cmd::prelude::*;
use eth2_keystore::Keystore;
use eth_staking_smith::ValidatorExports;
use std::process::Command;
/*
    generate 1 validator with new mnemonic (with no withdrawal address specified, i.e. the address is derived from the public key)
*/
#[test]
fn test_new_mnemonic_testcase1() -> Result<(), Box<dyn std::error::Error>> {
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

    generated_deposit_data.validate();

    // decrypt keystore with expected password to derive private key
    let encoded_private_key = decrypt_generated_keystore(
        generated_validator_json.keystores.get(0).unwrap(),
        decryption_password,
    );
    assert_eq!(generated_private_key, &encoded_private_key);

    Ok(())
}

/*
    generate 1 validator overwriting withdrawal credentials with eth1 address
*/
#[test]
fn test_new_mnemonic_testcase2() -> Result<(), Box<dyn std::error::Error>> {
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

    generated_deposit_data.validate();

    // decrypt keystore with expected password to derive private key
    let encoded_private_key = decrypt_generated_keystore(
        generated_validator_json.keystores.get(0).unwrap(),
        decryption_password,
    );
    assert_eq!(generated_private_key, &encoded_private_key);

    Ok(())
}

/*
    generate 3 validators
*/
#[test]
fn test_new_mnemonic_multiple_validators_testcase3() -> Result<(), Box<dyn std::error::Error>> {
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

    for deposit_data in generated_deposit_datas {
        deposit_data.validate();
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
    generate 1 validator by passing in an existing bls credentials (to ensure correctness, we'll use the validator from testcase 1)
*/
#[test]
fn test_new_mnemonic_testcase4() -> Result<(), Box<dyn std::error::Error>> {
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

    generated_deposit_data.validate();

    // decrypt keystore with expected password to derive private key
    let encoded_private_key = decrypt_generated_keystore(
        generated_validator_json.keystores.get(0).unwrap(),
        decryption_password,
    );
    assert_eq!(generated_private_key, &encoded_private_key);

    Ok(())
}

/*
    generate 1 validator overwriting withdrawal credentials with eth1 credentials (to ensure correctness, we'll use the validator from testcase 2)
*/
#[test]
fn test_new_mnemonic_testcase5() -> Result<(), Box<dyn std::error::Error>> {
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
        .expect("could not get generated private key")
        .to_owned();

    generated_deposit_data.validate();

    // decrypt keystore with expected password to derive private key
    let encoded_private_key = decrypt_generated_keystore(
        generated_validator_json.keystores.get(0).unwrap(),
        decryption_password,
    );
    assert_eq!(generated_private_key, &encoded_private_key);

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
