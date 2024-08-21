use assert_cmd::prelude::*;
use std::process::Command;
use types::SignedVoluntaryExit;

/**

Command sequence to verify signature:

./target/debug/eth-staking-smith existing-mnemonic \
       --chain mainnet \
       --num_validators 1 \
       --mnemonic 'ski interest capable knee usual ugly duty exercise tattoo subway delay upper bid forget say'
{
  "deposit_data": [
    {
      "amount": 32000000000,
      "deposit_cli_version": "2.7.0",
      "deposit_data_root": "7ac103cb959b55dff155f7406393c3e6f1ba0011baee2b61bca00fdc3b2cb2c2",
      "deposit_message_root": "bfd9d2c616eb570ad3fd4d4caf169b88f80490d8923537474bf1f6c5cec5e56d",
      "fork_version": "00000000",
      "network_name": "mainnet",
      "pubkey": "8844cebb34d10e0e57f3c29ada375dafe14762ab85b2e408c3d6d55ce6d03317660bca9f2c2d17d8fbe14a2529ada1ea",
      "signature": "96ebebf92967a2b187e031062f5cb5128a2bfc42559bd9dfdd1e481a056b3ef2cfddf1a0381530286013e3893e097b02129113e62a94bedd250253eb766f010824d0be7616f51b9f7609972695231bcda1cabf7a6a2d60a07e14237f2b6096ab",
      "withdrawal_credentials": "0045b91b2f60b88e7392d49ae1364b55e713d06f30e563f9f99e10994b26221d"
    }
  ],
  "keystores": [],
  "mnemonic": {
    "seed": "ski interest capable knee usual ugly duty exercise tattoo subway delay upper bid forget say"
  },
  "private_keys": [
    "6d446ca271eb229044b9039354ecdfa6244d1a11615ec1a46fc82a800367de5d"
  ]
}

./ethdo validator exit --epoch 305658 --private-key=0x6d446ca271eb229044b9039354ecdfa6244d1a11615ec1a46fc82a800367de5d --offline --json | jq
{
  "message": {
    "epoch": "305658",
    "validator_index": "100"
  },
  "signature": "0xa74f22d26da9934c2a9c783799fb9e7bef49b3d7c3759a0683b52ee5d71516c0ecdbcc47703f11959c5e701a6c47194410bed800217bd4dd0dab1e0587b14551771accd04ff1c78302f9605f44c3894976c5b3537b70cb7ac9dcb5398dc22079"
}

cat offline-preparation.json
{
  "version": "3",
  "genesis_validators_root": "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
  "epoch": "305658",
  "genesis_fork_version": "0x00000000",
  "exit_fork_version": "0x03000000",
  "current_fork_version": "0x04000000",
  "bls_to_execution_change_domain_type": "0x0a000000",
  "voluntary_exit_domain_type": "0x04000000",
  "validators": [
    {
      "index": "100",
      "pubkey": "8844cebb34d10e0e57f3c29ada375dafe14762ab85b2e408c3d6d55ce6d03317660bca9f2c2d17d8fbe14a2529ada1ea",
      "state": "active_ongoing",
      "withdrawal_credentials": "0x0100000000000000000000000d369bb49efa5100fd3b86a9f828c55da04d2d50"
    }
  ]
}

*/

#[test]
fn test_presigned_exit_message() -> Result<(), Box<dyn std::error::Error>> {
    let chain = "mainnet";
    let expected_mnemonic = "ski interest capable knee usual ugly duty exercise tattoo subway delay upper bid forget say";
    let validator_start_index = "0";
    let validator_index = "100";
    let epoch = "305658";

    // run eth-staking-smith
    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("presigned-exit-message");
    cmd.arg("--chain");
    cmd.arg(chain);
    cmd.arg("--validator_start_index");
    cmd.arg(validator_start_index);
    cmd.arg("--validator_index");
    cmd.arg(validator_index);
    cmd.arg("--mnemonic");
    cmd.arg(expected_mnemonic);
    cmd.arg("--epoch");
    cmd.arg(epoch);

    cmd.assert().success();

    let output = &cmd.output()?.stdout;
    let command_output = std::str::from_utf8(output)?;

    let signed_voluntary_exit: SignedVoluntaryExit = serde_json::from_str(command_output)?;

    assert_eq!(
        signed_voluntary_exit.signature.to_string(),
        "0xa74f22d26da9934c2a9c783799fb9e7bef49b3d7c3759a0683b52ee5d71516c0ecdbcc47703f11959c5e701a6c47194410bed800217bd4dd0dab1e0587b14551771accd04ff1c78302f9605f44c3894976c5b3537b70cb7ac9dcb5398dc22079"
    );

    Ok(())
}
