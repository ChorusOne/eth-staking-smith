use assert_cmd::prelude::*;
use std::process::Command;
use types::SignedVoluntaryExit;

/**

Command sequence to verify signature:

./target/debug/eth-staking-smith existing-mnemonic \
       --chain mainnet \
       --num_validators 3 \
       --mnemonic 'ski interest capable knee usual ugly duty exercise tattoo subway delay upper bid forget say'
./target/debug/eth-staking-smith existing-mnemonic \
       --chain mainnet \
       --num_validators 3 \
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
    },
    {
      "amount": 32000000000,
      "deposit_cli_version": "2.7.0",
      "deposit_data_root": "21e499c8fe06ec48b410c9c8a05c65856a6f8a0059da638e959008c3a98a8863",
      "deposit_message_root": "c17da3de7a90e706f6299b35fd958c1c6cf47138073fa7d704405a7dea37e760",
      "fork_version": "00000000",
      "network_name": "mainnet",
      "pubkey": "8b9fc0882dc9257619f973fd7034d70f4fbdf7148600e7decb4ffc74536720e4fcb0853f855bd818bb881ca219682477",
      "signature": "b788c42fc128e92baf5f0347acba0b0608e6aa3c36a94ce8845afd8d557503ef418230d7a576b92c633c99ef9a44f27a05156c1166aec7e28487bdad98b574911b0f9848de8d881a062773e8f75b1ebdea86e6af9279ba7c62fb2f078e8e8f30",
      "withdrawal_credentials": "006ab1394ad6a99cd25e2f1f15da057cfde5025b066bcecc1afedc2a4cb36314"
    },
    {
      "amount": 32000000000,
      "deposit_cli_version": "2.7.0",
      "deposit_data_root": "dd07496493d9bc8d239c589ccb0e0c51a03a23934565629053b11806418fbbdb",
      "deposit_message_root": "7c86984887d258b74f446154ab40d0e83329309c15b824bd67420225a63d6ae4",
      "fork_version": "00000000",
      "network_name": "mainnet",
      "pubkey": "a15cc019cf4ce59f587d24bd58ae6011c8b638770c3c133cc9f081e161e7db01c92611f1a566b00208dd1e709f6ec716",
      "signature": "b6312a2a9fc8427391d69e94b2d6c77db0bf78e3b1ffe368c833d1abf9f6e73e00b98d22e311fe44f7f012aa857339d715b5bbde6b28c76af3fff64f951b9a413e94a0d3729d358037bbfabd6b1905be503a91d8b19cb4fa912e2e7ddeaf044d",
      "withdrawal_credentials": "0020e45be0f34aa53665c8f8d98b60163c9ba0b0549199172bb1a7c6f544f061"
    }
  ],
  "keystores": [],
  "mnemonic": {
    "seed": "ski interest capable knee usual ugly duty exercise tattoo subway delay upper bid forget say"
  },
  "private_keys": [
    "6d446ca271eb229044b9039354ecdfa6244d1a11615ec1a46fc82a800367de5d",
    "17432f01cff4c21d848183909a300a776a57f75827414a853a52f0cbdb212f7e",
    "338cc9dd5d27a9385e79487f597a72250e0f4fd2d6271ea012b8520b5455fc49"
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

./ethdo validator exit --epoch 305658 --private-key=0x338cc9dd5d27a9385e79487f597a72250e0f4fd2d6271ea012b8520b5455fc49 --offline --json | jq

{
  "message": {
    "epoch": "305658",
    "validator_index": "200"
  },
  "signature": "0x8db88aabdd8f03cebba47cf3df7dd5e06ab9a49f57fc209a00cb73c5ecdea192b6ab0c5965ad8e7b6b63b9d397be3df40ea84150f2ed13ca9e0ba382c24f583ca921ff0364f18e51444838992d628623598c7c12122ff46d
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
    },
    {
      "index": "200",
      "pubkey": "a15cc019cf4ce59f587d24bd58ae6011c8b638770c3c133cc9f081e161e7db01c92611f1a566b00208dd1e709f6ec716",
      "state": "active_ongoing",
      "withdrawal_credentials": "0x0100000000000000000000000d369bb49efa5100fd3b86a9f828c55da04d2d50"
    }
  ]
}

*/

#[test]
fn test_batch_presigned_exit_message() -> Result<(), Box<dyn std::error::Error>> {
    let chain = "mainnet";
    let expected_mnemonic = "ski interest capable knee usual ugly duty exercise tattoo subway delay upper bid forget say";
    let seed_beacon_mapping = "0:100,2:200";
    let epoch = "305658";

    // run eth-staking-smith
    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("batch-presigned-exit-message");
    cmd.arg("--chain");
    cmd.arg(chain);
    cmd.arg("--seed_beacon_mapping");
    cmd.arg(seed_beacon_mapping);
    cmd.arg("--mnemonic");
    cmd.arg(expected_mnemonic);
    cmd.arg("--epoch");
    cmd.arg(epoch);

    cmd.assert().success();

    let output = &cmd.output()?.stdout;
    let command_output = std::str::from_utf8(output)?;

    let signed_voluntary_exits: Vec<SignedVoluntaryExit> = serde_json::from_str(command_output)?;
    let signed_voluntary_exit1 = signed_voluntary_exits.get(0).unwrap();
    let signed_voluntary_exit2 = signed_voluntary_exits.get(1).unwrap();

    let mut signatures = vec![
        signed_voluntary_exit1.signature.to_string(),
        signed_voluntary_exit2.signature.to_string(),
    ];
    signatures.sort();

    assert_eq!(
      signatures,
      vec![
        "0x8db88aabdd8f03cebba47cf3df7dd5e06ab9a49f57fc209a00cb73c5ecdea192b6ab0c5965ad8e7b6b63b9d397be3df40ea84150f2ed13ca9e0ba382c24f583ca921ff0364f18e51444838992d628623598c7c12122ff46da795c000ae15dd65",
        "0xa74f22d26da9934c2a9c783799fb9e7bef49b3d7c3759a0683b52ee5d71516c0ecdbcc47703f11959c5e701a6c47194410bed800217bd4dd0dab1e0587b14551771accd04ff1c78302f9605f44c3894976c5b3537b70cb7ac9dcb5398dc22079",
      ]
    );

    Ok(())
}
