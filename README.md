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

## Converting your BLS 0x00 withdrawal address 

Ethereum will be implementing a push-based approach for withdrawals, see [EIP-4895 docs](https://eips.ethereum.org/EIPS/eip-4895).

Those who have configured a BLS withdrawal address (0x00) in the validators deposit contract, will have to undergo the following steps: 
1. generate a signed message to trigger BLS to execution address
2. send the signed message to the beacon node

You can use `eth-staking-smith` as follows to convert your address:

### Command to generate SignedBLSToExecutionChange

```
./target/debug/eth-staking-smith bls-to-execution-change --chain mainnet --mnemonic "entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup" --validator_start_index 0 --validator_index 100 --withdrawal_credentials "0x0045b91b2f60b88e7392d49ae1364b55e713d06f30e563f9f99e10994b26221d"
--execution_address "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
```

Note that --validator-index and --validator-start-index are two distinct parameter, the former being index of validator on Beacon chain, and the latter is the index of validator private key derived from the seed

### Command to send SignedBLSToExecutionChange request to Beacon node

```
curl -H "Content-Type: application/json" -d '{
  "message": {
    "validator_index": 100,
    "from_bls_pubkey": "0x0045b91b2f60b88e7392d49ae1364b55e713d06f30e563f9f99e10994b26221d",
    "to_execution_address": "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
  },
  "signature": "0x9220e5badefdfe8abc36cae01af29b981edeb940ff88c438f72c8af876fbd6416138c85f5348c5ace92a081fa15291aa0ffb856141b871dc807f3ec2fe9c8415cac3d76579c61455ab3938bc162e139d060c8aa13fcd670febe46bf0bb579c5a"
}' http://localhost:3500/eth/v1/beacon/pool/bls_to_execution_change
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