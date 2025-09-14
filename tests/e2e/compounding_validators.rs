use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DepositDataJson {
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

use assert_cmd::prelude::*;
use eth_staking_smith::{
    utils::{
        compounding_withdrawal_creds_from_pk, is_compounding_withdrawal_credentials,
        validate_deposit_amount,
    },
    ValidatorExports,
};
use std::process::Command;
use std::str::FromStr;
use types::PublicKeyBytes;

#[test]
fn test_deposit_amount_validation_compounding() {
    // Valid compounding validator amounts
    assert!(validate_deposit_amount(32_000_000_000, true).is_ok()); // 32 ETH
    assert!(validate_deposit_amount(64_000_000_000, true).is_ok()); // 64 ETH
    assert!(validate_deposit_amount(1_000_000_000_000, true).is_ok()); // 1000 ETH
    assert!(validate_deposit_amount(2_048_000_000_000, true).is_ok()); // 2048 ETH (max)

    // Invalid compounding validator amounts
    assert!(validate_deposit_amount(31_999_999_999, true).is_err());
    assert!(validate_deposit_amount(2_048_000_000_001, true).is_err());
    assert!(validate_deposit_amount(0, true).is_err());
}

#[test]
fn test_deposit_amount_validation_non_compounding() {
    // Only 32 ETH allowed for non-compounding validators
    assert!(validate_deposit_amount(32_000_000_000, false).is_ok()); // Exactly 32 ETH

    // All other amounts should fail
    assert!(validate_deposit_amount(31_999_999_999, false).is_err()); // Just under 32 ETH
    assert!(validate_deposit_amount(32_000_000_001, false).is_err()); // Just over 32 ETH
    assert!(validate_deposit_amount(64_000_000_000, false).is_err()); // 64 ETH
    assert!(validate_deposit_amount(0, false).is_err()); // Zero
}

#[test]
fn test_is_compounding_withdrawal_credentials() {
    // Test 0x02 prefixed credentials (compounding)
    assert!(is_compounding_withdrawal_credentials(
        "02abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    ));
    assert!(is_compounding_withdrawal_credentials(
        "0x02abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    ));

    // Test non-compounding credentials
    assert!(!is_compounding_withdrawal_credentials(
        "00abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    )); // 0x00
    assert!(!is_compounding_withdrawal_credentials(
        "01000000000000000000000071c7656ec7ab88b098defb751b7401b5f6d8976f"
    )); // 0x01
    assert!(!is_compounding_withdrawal_credentials(
        "03abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    )); // 0x03
}

#[test]
fn test_compounding_withdrawal_creds_generation() {
    // Test generating 0x02 withdrawal credentials from public key
    // Using a valid 48-byte (96 hex char) BLS public key from test data
    let test_pubkey_str = "0x8c239d313e3f4efb1ed937e7560dfaabeb6def6b88001357d5e9a3c33fdb022f7b028085c09451667f06b6b849c71ce8";
    let pubkey = PublicKeyBytes::from_str(test_pubkey_str).expect("Valid public key");

    let compounding_creds = compounding_withdrawal_creds_from_pk(&pubkey);

    assert!(compounding_creds.starts_with("02"));
    assert_eq!(compounding_creds.len(), 64);
    assert!(hex::decode(&compounding_creds).is_ok());
}

/*
    Test CLI with explicit --compounding flag - should generate 0x02 compounding validators
*/
#[test]
#[serial_test::serial]
fn test_cli_explicit_compounding_validator() -> Result<(), Box<dyn std::error::Error>> {
    let expected_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    std::env::set_var("MNEMONIC", expected_mnemonic);

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;
    cmd.args(&[
        "existing-mnemonic",
        "--chain",
        "holesky",
        "--num_validators",
        "1",
        "--compounding",
    ]);

    let output = cmd.output()?;
    let stdout = String::from_utf8(output.stdout)?;

    // Parse the JSON output
    let validator_exports: ValidatorExports = serde_json::from_str(&stdout)?;

    // Verify we got one validator
    assert_eq!(validator_exports.deposit_data.len(), 1);

    // Verify --compounding flag generates 0x02 credentials
    let deposit_data = &validator_exports.deposit_data[0];
    assert!(
        deposit_data.withdrawal_credentials.starts_with("02"),
        "--compounding flag should generate 0x02 withdrawal credentials, got: {}",
        deposit_data.withdrawal_credentials
    );

    // Verify default 32 ETH amount
    assert_eq!(deposit_data.amount, 32_000_000_000);

    Ok(())
}

/*
    Test CLI with custom ETH deposit amount
*/
#[test]
#[serial_test::serial]
fn test_cli_custom_eth_amount() -> Result<(), Box<dyn std::error::Error>> {
    let expected_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    std::env::set_var("MNEMONIC", expected_mnemonic);

    let test_amounts = vec![64, 100, 500, 2048];

    for eth_amount in test_amounts {
        let mut cmd = Command::cargo_bin("eth-staking-smith")?;
        cmd.args(&[
            "existing-mnemonic",
            "--chain",
            "holesky",
            "--num_validators",
            "1",
            "--deposit_amount",
            &eth_amount.to_string(),
            "--compounding",
        ]);

        let output = cmd.output()?;
        let stdout = String::from_utf8(output.stdout)?;

        // Parse the JSON output
        let validator_exports: ValidatorExports = serde_json::from_str(&stdout)?;

        // Verify the deposit amount is correctly set (ETH converted to Gwei)
        let expected_gwei = eth_amount * 1_000_000_000;
        let deposit_data = &validator_exports.deposit_data[0];
        assert_eq!(
            deposit_data.amount, expected_gwei,
            "Expected {} ETH ({} Gwei), got {} Gwei",
            eth_amount, expected_gwei, deposit_data.amount
        );

        // Should still generate 0x02 credentials by default
        assert!(deposit_data.withdrawal_credentials.starts_with("02"));
    }

    Ok(())
}

/*
    Test CLI with explicit legacy BLS withdrawal credentials
*/
#[test]
#[serial_test::serial]
fn test_cli_legacy_bls_credentials() -> Result<(), Box<dyn std::error::Error>> {
    let expected_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    std::env::set_var("MNEMONIC", expected_mnemonic);

    let bls_credentials = "0x0012345678901234567890123456789012345678901234567890123456789012";

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;
    cmd.args(&[
        "existing-mnemonic",
        "--chain",
        "holesky",
        "--num_validators",
        "1",
        "--withdrawal_credentials",
        bls_credentials,
    ]);

    let output = cmd.output()?;
    let stdout = String::from_utf8(output.stdout)?;

    // Parse the JSON output
    let validator_exports: ValidatorExports = serde_json::from_str(&stdout)?;

    // Verify the withdrawal credentials are set correctly
    let deposit_data = &validator_exports.deposit_data[0];
    assert_eq!(
        deposit_data.withdrawal_credentials,
        "0012345678901234567890123456789012345678901234567890123456789012"
    );

    // Should be 32 ETH (only amount allowed for non-compounding)
    assert_eq!(deposit_data.amount, 32_000_000_000);

    Ok(())
}

/*
    Test CLI boundary conditions - minimum and maximum deposits
*/
#[test]
#[serial_test::serial]
fn test_cli_boundary_conditions() -> Result<(), Box<dyn std::error::Error>> {
    let expected_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    std::env::set_var("MNEMONIC", expected_mnemonic);

    // Test minimum (32 ETH)
    let mut cmd = Command::cargo_bin("eth-staking-smith")?;
    cmd.args(&[
        "existing-mnemonic",
        "--chain",
        "holesky",
        "--num_validators",
        "1",
        "--deposit_amount",
        "32",
    ]);

    let output = cmd.output()?;
    assert!(output.status.success(), "32 ETH deposit should succeed");

    let stdout = String::from_utf8(output.stdout)?;
    let validator_exports: ValidatorExports = serde_json::from_str(&stdout)?;
    assert_eq!(validator_exports.deposit_data[0].amount, 32_000_000_000);

    // Test maximum (2048 ETH) - requires compounding
    let mut cmd = Command::cargo_bin("eth-staking-smith")?;
    cmd.args(&[
        "existing-mnemonic",
        "--chain",
        "holesky",
        "--num_validators",
        "1",
        "--deposit_amount",
        "2048",
        "--compounding",
    ]);

    let output = cmd.output()?;
    assert!(output.status.success(), "2048 ETH deposit should succeed");

    let stdout = String::from_utf8(output.stdout)?;
    let validator_exports: ValidatorExports = serde_json::from_str(&stdout)?;
    assert_eq!(validator_exports.deposit_data[0].amount, 2_048_000_000_000);

    Ok(())
}

/*
    Test that new-mnemonic command uses 0x00 credentials by default (backward compatibility)
*/
#[test]
fn test_cli_new_mnemonic_default_bls() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("eth-staking-smith")?;
    cmd.args(&[
        "new-mnemonic",
        "--chain",
        "holesky",
        "--num_validators",
        "1",
    ]);

    let output = cmd.output()?;
    let stdout = String::from_utf8(output.stdout)?;

    // Parse the JSON output
    let validator_exports: ValidatorExports = serde_json::from_str(&stdout)?;

    // Verify default behavior generates 0x00 BLS credentials (backward compatibility)
    let deposit_data = &validator_exports.deposit_data[0];
    assert!(
        deposit_data.withdrawal_credentials.starts_with("00"),
        "New mnemonic should generate 0x00 BLS withdrawal credentials by default, got: {}",
        deposit_data.withdrawal_credentials
    );

    Ok(())
}

/*
    Test multiple validators with compounding amounts
*/
#[test]
#[serial_test::serial]
fn test_cli_multiple_compounding_validators() -> Result<(), Box<dyn std::error::Error>> {
    let expected_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    std::env::set_var("MNEMONIC", expected_mnemonic);

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;
    cmd.args(&[
        "existing-mnemonic",
        "--chain",
        "holesky",
        "--num_validators",
        "3",
        "--deposit_amount",
        "100",
        "--compounding",
    ]);

    let output = cmd.output()?;
    let stdout = String::from_utf8(output.stdout)?;

    // Parse the JSON output
    let validator_exports: ValidatorExports = serde_json::from_str(&stdout)?;

    // Verify we got 3 validators
    assert_eq!(validator_exports.deposit_data.len(), 3);

    // Verify all have correct amount and compounding credentials
    for (i, deposit_data) in validator_exports.deposit_data.iter().enumerate() {
        assert_eq!(
            deposit_data.amount, 100_000_000_000,
            "Validator {} should have 100 ETH",
            i
        );
        assert!(
            deposit_data.withdrawal_credentials.starts_with("02"),
            "Validator {} should have 0x02 credentials",
            i
        );
    }

    Ok(())
}

/*
    Test that new-mnemonic command uses 0x02 credentials with --compounding flag
*/
#[test]
fn test_cli_new_mnemonic_compounding_flag() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("eth-staking-smith")?;
    cmd.args(&[
        "new-mnemonic",
        "--chain",
        "holesky",
        "--num_validators",
        "1",
        "--compounding",
    ]);

    let output = cmd.output()?;
    let stdout = String::from_utf8(output.stdout)?;

    // Parse the JSON output
    let validator_exports: ValidatorExports = serde_json::from_str(&stdout)?;

    // Verify --compounding flag generates 0x02 credentials
    let deposit_data = &validator_exports.deposit_data[0];
    assert!(
        deposit_data.withdrawal_credentials.starts_with("02"),
        "New mnemonic with --compounding should generate 0x02 withdrawal credentials, got: {}",
        deposit_data.withdrawal_credentials
    );

    Ok(())
}
