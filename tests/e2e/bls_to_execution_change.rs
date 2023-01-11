use assert_cmd::prelude::*;
use eth_staking_smith::bls_to_execution_change::SignedBLSToExecutionChangeExport;
use std::process::Command;

/*
    create SignedBLSToExecutionChange message for existing mnemonic
*/
#[test]
fn test_bls_to_execution_change() -> Result<(), Box<dyn std::error::Error>> {
    let chain = "goerli";
    let expected_mnemonic = "ski interest capable knee usual ugly duty exercise tattoo subway delay upper bid forget say";
    let validator_index = "0";
    let execution_address = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F";
    let bls_withdrawal_credentials =
        "0x0045b91b2f60b88e7392d49ae1364b55e713d06f30e563f9f99e10994b26221d";
    // run eth-staking-smith
    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("bls-to-execution-change");
    cmd.arg("--chain");
    cmd.arg(chain);
    cmd.arg("--validator_index");
    cmd.arg(validator_index);
    cmd.arg("--mnemonic");
    cmd.arg(expected_mnemonic);
    cmd.arg("--bls_withdrawal_credentials");
    cmd.arg(bls_withdrawal_credentials);
    cmd.arg("--execution_address");
    cmd.arg(execution_address);

    cmd.assert().success();

    // read generated output

    let output = &cmd.output()?.stdout;
    let command_output = std::str::from_utf8(output)?;

    let signed_bls_to_execution_change: SignedBLSToExecutionChangeExport =
        serde_json::from_str(command_output)?;

    assert_eq!(0, signed_bls_to_execution_change.message.validator_index);
    assert_eq!(
        "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
        signed_bls_to_execution_change.message.to_execution_address
    );
    assert_eq!(
        "0x0045b91b2f60b88e7392d49ae1364b55e713d06f30e563f9f99e10994b26221d",
        signed_bls_to_execution_change.message.from_bls_pubkey
    );

    Ok(())
}

// negative test inputs
