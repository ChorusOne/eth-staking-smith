eth-staking-smith
================

# Introduction

Command-line tool to facilitate key and deposit data generation for ethereum proof-of-stake validators.

Why we need yet another keystore / deposit tool:

1. eth-staking-smith is written in Rust
2. ability to use as a library to automate key and deposit data generation
3. opt-out of writing to filesystem for better security
4. defer entropy collection to operating system by using `getrandom`
5. ability to overwrite withdrawal credentials for new and existing mnemonic
6. ability to generate a `SignedBLSToExecutionChange` message to convert your BLS withdrawal address `0x00` to an execution `0x01` address

# Blog post

[Performant Ethereum validator key management](https://medium.com/chorus-one/eth-staking-smith-1ca8374571b5?source=rss-------1)

# Usage

```
cargo build
```

## New mnemonic 

Generate key and deposit data with a new mnemonic:

```
./target/debug/eth-staking-smith new-mnemonic --help
```

### Example command:

```
./target/debug/eth-staking-smith new-mnemonic --chain mainnet --keystore_password testtest --num_validators 1
```

## Existing mnemonic 

Regenerate key and deposit data with existing mnemonic:

```
./target/debug/eth-staking-smith existing-mnemonic --help
```

### Example command:

```
./target/debug/eth-staking-smith existing-mnemonic --chain mainnet --keystore_password testtest --mnemonic "entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup" --num_validators 1 --withdrawal_credentials "0x0100000000000000000000000000000000000000000000000000000000000001"
```


## Passing mnemonic as environment variable

It is not always desirable to pass mnemonic as CLI argument, because
it can be either mistakenly recorded in shell history or recorded by
the monitoring software that could be logging process arguments on host.

This is why all commands that accept `--mnemonic` argument also support
taking mnemonic as environment variable `MNEMONIC`

For example, `existing-mnemonic` command works like follows with mnemonic in plain text:
```
./target/debug/eth-staking-smith existing-mnemonic --chain mainnet --keystore_password testtest --mnemonic "entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup" --num_validators 1 --withdrawal_credentials "0x0100000000000000000000000000000000000000000000000000000000000001"
```

And, as follows with mnemonic as an environment variable `MNEMONIC`:

```
export MNEMONIC="entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup"
./target/debug/eth-staking-smith existing-mnemonic --chain mainnet --keystore_password testtest --num_validators 1 --withdrawal_credentials "0x0100000000000000000000000000000000000000000000000000000000000001"
```

Or, it makes possible possible to have bash prompt for mnemonic with hidden input like follows

```
echo "Please enter your mnemonic" ; read -s MNEMONIC ; export MNEMONIC
Please enter your mnemonic
./target/debug/eth-staking-smith existing-mnemonic --chain mainnet --keystore_password testtest --num_validators 1 --withdrawal_credentials "0x0100000000000000000000000000000000000000000000000000000000000001"
```

## Using custom testnet config

Both `existing-mnemonic` and `new-mnemonic` commands support generating validators for custom testnets.
To reference custom testnet config yaml file, pass `--testnet_config` parameter
with that config as value, and omit `--chain` parameter:

### Example command
```
./target/debug/eth-staking-smith new-mnemonic --testnet_config /etc/privatenet/config.yaml --keystore_password testtest --num_validators 1 --withdrawal_credentials "0x0100000000000000000000000000000000000000000000000000000000000001"
```

## Converting your BLS 0x00 withdrawal address 

Ethereum will be implementing a push-based approach for withdrawals, see [EIP-4895 docs](https://eips.ethereum.org/EIPS/eip-4895).

Those who have configured a BLS withdrawal address (0x00) in the validators deposit contract, will have to undergo the following steps: 
1. generate a signed message to trigger BLS to execution address
2. send the signed message to the beacon node

You can use `eth-staking-smith` as follows to convert your address:

### Command to generate SignedBLSToExecutionChange

```
./target/debug/eth-staking-smith bls-to-execution-change --chain mainnet --mnemonic "entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup" --validator_start_index 0 --validator_index 100 --withdrawal_credentials "0x0045b91b2f60b88e7392d49ae1364b55e713d06f30e563f9f99e10994b26221d" \
--execution_address "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
```

Note that --validator-index and --validator-start-index are two distinct parameter, the former being index of validator on Beacon chain, and the latter is the index of validator private key derived from the seed


### Command to send SignedBLSToExecutionChange request to Beacon node

```
./target/debug/eth-staking-smith bls-to-execution-change --chain mainnet --mnemonic "entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup" --validator_start_index 0 --validator_index 100 --withdrawal_credentials "0x0045b91b2f60b88e7392d49ae1364b55e713d06f30e563f9f99e10994b26221d" \
--execution_address "0x71C7656EC7ab88b098defB751B7401B5f6d8976F" \
--beacon-node-uri http://beacon-node.local:5052
```

Notice `--beacon-node-uri` parameter which makes payload to be sent to beacon node

## Generating pre-signed exit message

It is possible to create pre-signed voluntary exit message for every validator that
is generated from some known mnemonic, given the minimum epoch for exit to trigger.

Use `eth-staking-smith` via command line like:

### Command to generate presigned exit message

```
./target/debug/eth-staking-smith presigned-exit-message --chain mainnet --mnemonic "entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup" --validator_seed_index 0 --validator_beacon_index 100 --epoch 300000
```

Note that --validator-beacon-index and --validator-seed-index are two distinct parameter, the former being index of validator on Beacon chain, and the latter is the index of validator private key derived from the seed

It is also possible to directly pass private key with `--private-key` parameter instead,
then `--mnemonic` and `--validator-seed-index` may be omitted like follows

```
./target/debug/eth-staking-smith presigned-exit-message --chain mainnet --private-key "0x3f3e0a69a6a66aeaec606a2ccb47c703afb2e8ae64f70a1650c03343b06e8f0c" --validator_beacon_index 100 --epoch 300000
```

### Command to send VoluntaryExitMessage request to Beacon node

```
./target/debug/eth-staking-smith presigned-exit-message --chain mainnet --mnemonic "entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup" --validator_seed_index 0 --validator_beacon_index 100 --epoch 300000 \
--beacon-node-uri http://beacon-node.local:5052
```

Notice `--beacon-node-uri` parameter which makes payload to be sent to beacon node


### Command to generate batch of presigned exit messages exit message

Sometimes it may be desirable to generate batch of presigned exit messages for the
validators created from the same mnemonic.

```
./target/debug/eth-staking-smith batch-presigned-exit-message --chain=mainnet --mnemonic='ski interest capable knee usual ugly duty exercise tattoo subway delay upper bid forget say' --epoch 305658  --seed-beacon-mapping='0:100,2:200'
```

Instead of accepting single `--validator-seed-index` and `--validator-beacon-index` pair of parameter,
it takes comma-separated mapping of validator seed index to validator beacon index in `--seed-beacon-mapping`
parameter. Keys and values in mapping should be separated by colon, so mapping of `0:100,2:200`
will read as follows

- validator with seed index `0` with given mnemonic has index `100` on beacon chain
- validator with seed index `1` has beacon index `200`

## Exporting CLI standard output into common keystores folder format

Most validator clients recognize the keystore folder format,
produced by upstream Python deposit CLI. While `eth-staking-smith` outputs
all validator data into standard output, allowing for better security in
enterprise setups, for small and individual stakers this is not convenient,
as they need to be able to import validator keys directly into validator client.

To address such needs, `eth-staking-smith` provides convenience Python3 script
to export JSON validator output into common keystore folder format. It should
work on any box with Python 3.10+ installed.

```
mkdir validator_keys/
./target/debug/eth-staking-smith new-mnemonic --chain holesky --num_validators 2 \
  --keystore_password test > validator_secrets.json
cat validator_secrets.json | python3 scripts/generate_keys_folder.py
cat validator_secrets.json | jq .mnemonic.seed > mnemonic.txt
rm validator_secrets.json
echo "MAKE SURE TO BACK UP mnemonic.text IN THE SAFE PLACE"

ls validator_keys/
deposit_data-1720014619.json  keystore-m_12381_3600_0_0_0-1720014619.json  keystore-m_12381_3600_1_0_0-1720014619.json
```

The contents of `validator_keys/` folder might be imported into most
validator clients, for example Lighthouse import command will look like that:

```
echo "test" > ./password.txt
lighthouse account validator import \
  --network holesky --reuse-password
  --directory validator_keys/ --password-file ./password.txt
```


# Implementation Details 
To avoid heavy lifting, we're interfacing [Lighthouse account manager](https://github.com/sigp/lighthouse/blob/stable/account_manager), but optimizing it in a way so all operations are done in memory and key material is never written to filesystem during the generation to cater for our use case.

## Entropy gathering
When you run the command `new-mnemonic` a new mnemonic is generated from a seed. Entropy collection for the given seed is done by using the platform dependent `getrandom(2)` system call. On Linux, getrandom(2) pulls entropy from cryptographically secure RNG provided by Linux kernel, which implements ChaCha based PRNG algorithm that reseeds itself from multiple hardware TRNG sources with 300Hz frequency. If you're running on anything other than Linux, look up target platform implementation in https://github.com/rust-random/getrandom for details.

## Ability to tweak performance parameters
Specifically, we have two arguments you may use for improving performance during key generation: 
1. You can opt-out of generating keystores by omitting the optional `--keystore_password` argument. Depending on how you manage your keys you would either store them as keystore files or simply store the private keys in vault. If you're doing the latter it would be more optimal for you to bypass the keystore generation and only retrieve the private keys such that you can store them in vault.
2. To speed up the process of keystore generation, you may want to choose your key derivation function depending on your use case with `scrypt` with higher security parameters and slower performance vs `pbkdf2` achieving better performance with lower security parameters compared to `scrypt`.

# Testing 

```
cargo test
```

## E2E Tests
To test our code e2e, we've generated files using the [staking deposit cli v2.3.0](https://github.com/ethereum/staking-deposit-cli/releases/tag/v2.3.0) and are comparing the outputs during our tests. This is to guarantee that we're meeting the same criteria. Further error cases are checked in unit tests within the dedicated modules.

# Glossary

| Term      | Description |
| ----------- | ----------- |
| Wallet      | Interface to manage accounts       |
| Account   | public/private keypair that points to your funds        |
| keystore file   | encrypted version of your private key in JSON funds        |
| key derviation function (kdf)   |  A Key Derivation Function lets you encrypt your keystore file with a password that you chose when running the cli. Eth staking smith supports `scrypt` or `pbkdf2` and will run the latter by default for improved performance.      |
| decryption key   |    used to encrypt/decrypt keystore file    |
| mnemonic phrase / seed phrase / seed words   | 12 or 24 word phrase to access infinite number of accounts, used to derive multiple private keys        |
| seed   | secret value used to derive HD wallet addresses from a mnemonic phrase (BIP39 standard)       |
| withdrawal credentials   |    Withdrawal Credentials is a 32-byte field in the deposit data, for verifying the destination of valid withdrawals. Currently, there are two types of withdrawals: BLS withdrawal (with a 00 prefix) and Ethereum withdrawals (with a 01 prefix). By default the former will be generated, however Ethereum is planning to fully move to 01 credentials once withdrawals become available |
| withdrawal address   |  Address for which withdrawal credentials should be generated. Eth staking smith allows execution addresses with the format `^(0x[a-fA-F0-9]{40})$` |


## Backwards compatibility
This project aims to present state-of-art Ethereum staking experience,
and does not follow semver approach for new releases.
Instead, backwards compatibility is provided on best-effort basis for both
library and command line interfaces, and every release that adds new
functionality can be treated as major release.

Interfaces may change as result of implementing new features, and/or
backwards incompatible changes in Ethereum protocol.

It is recommended to pin release version for users of command line interface,
and pin specific git commit of `eth-staking-smith` for library interface users.
