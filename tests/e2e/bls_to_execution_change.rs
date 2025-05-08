use assert_cmd::prelude::*;
use eth_staking_smith::utils::withdrawal_creds_from_pk;
use std::process::Command;
use types::SignedBlsToExecutionChange;

/*
    python3 staking_deposit/deposit.py generate-bls-to-execution-change

    ***Using the tool on an offline and secure device is highly recommended to keep your mnemonic safe.***

    Please choose your language ['1. العربية', '2. ελληνικά', '3. English', '4. Français', '5. Bahasa melayu', '6. Italiano', '7. 日本語', '8. 한국어', '9. Português do Brasil', '10. român', '11. Türkçe', '12. 简体中文']:  [English]:
    Please choose the (mainnet or testnet) network/chain name ['mainnet', 'goerli', 'sepolia', 'zhejiang', 'holesky']:  [mainnet]: holesky
    Please enter your mnemonic separated by spaces (" "). Note: you only need to enter the first 4 letters of each word if you'd prefer.: ski interest capable knee usual ugly duty exercise tattoo subway delay upper bid forget say
    Please enter the index position for the keys to start generating withdrawal credentials in ERC-2334 format. [0]: 0
    Please enter a list of the validator index number(s) of your validator(s) as identified on the beacon chain. Split multiple items with whitespaces or commas.: 100
    Please enter a list of the old BLS withdrawal credentials of your validator(s). Split multiple items with whitespaces or commas. The withdrawal credentials are in hexadecimal encoded form.: 0x0045b91b2f60b88e7392d49ae1364b55e713d06f30e563f9f99e10994b26221d
    Please enter the 20-byte execution address for the new withdrawal credentials. Note that you CANNOT change it once you have set it on chain.: 0x71C7656EC7ab88b098defB751B7401B5f6d8976F

    **[Warning] you are setting an Eth1 address as your withdrawal address. Please ensure that you have control over this address.**

    Repeat your execution address for confirmation.: 0x71C7656EC7ab88b098defB751B7401B5f6d8976F

*/
#[test]
fn test_bls_to_execution_change() -> Result<(), Box<dyn std::error::Error>> {
    let chain = "holesky";
    let expected_mnemonic = "ski interest capable knee usual ugly duty exercise tattoo subway delay upper bid forget say";
    let validator_start_index = "0";
    let validator_index = "100";
    let execution_address = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F";
    let bls_withdrawal_credentials =
        "0x0045b91b2f60b88e7392d49ae1364b55e713d06f30e563f9f99e10994b26221d";
    // run eth-staking-smith
    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("bls-to-execution-change");
    cmd.arg("--chain");
    cmd.arg(chain);
    cmd.arg("--validator_seed_index");
    cmd.arg(validator_start_index);
    cmd.arg("--validator_beacon_index");
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

    let signed_bls_to_execution_changes: Vec<SignedBlsToExecutionChange> =
        serde_json::from_str(command_output)?;
    assert_eq!(1, signed_bls_to_execution_changes.len());
    let signed_bls_to_execution_change = signed_bls_to_execution_changes.first().unwrap();

    assert_eq!(100, signed_bls_to_execution_change.message.validator_index);
    assert_eq!(
        "0x71C7656EC7ab88b098defB751B7401B5f6d8976F".to_lowercase(),
        format!(
            "0x{}",
            hex::encode(signed_bls_to_execution_change.message.to_execution_address)
        )
    );

    assert_eq!(
        "0x0045b91b2f60b88e7392d49ae1364b55e713d06f30e563f9f99e10994b26221d",
        format!(
            "0x{}",
            withdrawal_creds_from_pk(&signed_bls_to_execution_change.message.from_bls_pubkey)
        )
    );

    assert_eq!(
        "0xb9e6fcdf66962fbaeec762908e7c986c154ba2274fdfe307603d71c465acda49af98a75aa62743fc59a71e678fccd433164247130c1cede0832a17cc61fc21204ec83c7f8fd76848d6520805939547b4c677fca85f98d1f749c428814fd6a6c5",
        signed_bls_to_execution_change.signature.to_string()
    );

    Ok(())
}

#[test]
fn test_bls_to_execution_change_send_beacon_node() -> Result<(), Box<dyn std::error::Error>> {
    let server = httpmock::MockServer::start();

    let beacon_node_mock = server.mock(|when, then| {
        when.method(httpmock::Method::POST)
            .path("/eth/v1/beacon/pool/bls_to_execution_changes")
            .json_body(serde_json::json!([
                {
                    "message": {
                        "from_bls_pubkey": "0x958823db41e63bdb54b8445e454f24a592a44faef7bf1161c482c254d36cd2ffb027af3cc87817064c6a09f54acec5a0",
                        "to_execution_address": "0x71C7656EC7ab88b098defB751B7401B5f6d8976F".to_lowercase(),
                        "validator_index": "100",
                    },
                    "signature": "0xb9e6fcdf66962fbaeec762908e7c986c154ba2274fdfe307603d71c465acda49af98a75aa62743fc59a71e678fccd433164247130c1cede0832a17cc61fc21204ec83c7f8fd76848d6520805939547b4c677fca85f98d1f749c428814fd6a6c5"
                }
            ]));
        then.status(200);
    });

    let chain = "holesky";
    let expected_mnemonic = "ski interest capable knee usual ugly duty exercise tattoo subway delay upper bid forget say";
    let validator_start_index = "0";
    let validator_index = "100";
    let execution_address = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F";
    let bls_withdrawal_credentials =
        "0x0045b91b2f60b88e7392d49ae1364b55e713d06f30e563f9f99e10994b26221d";
    // run eth-staking-smith
    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("bls-to-execution-change");
    cmd.arg("--chain");
    cmd.arg(chain);
    cmd.arg("--validator_seed_index");
    cmd.arg(validator_start_index);
    cmd.arg("--validator_beacon_index");
    cmd.arg(validator_index);
    cmd.arg("--mnemonic");
    cmd.arg(expected_mnemonic);
    cmd.arg("--bls_withdrawal_credentials");
    cmd.arg(bls_withdrawal_credentials);
    cmd.arg("--execution_address");
    cmd.arg(execution_address);
    cmd.arg("--beacon-node-uri");
    cmd.arg(server.base_url());

    cmd.assert().success();

    // verify request path and body

    beacon_node_mock.assert();

    Ok(())
}
