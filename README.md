eth-staking-smith
================

# Introduction

Command-line tool to facilitate key and deposit data generation for ethereum proof-of-stake validators.

Why we need yet another keystore / deposit tool:

1. eth-staking-smith is written in Rust
2. ability to use as a library to automate key and deposit data generation
3. opt-out of writing to filesystem for better security
4. defer entropy collection to operating system by using `getrandom`
4. ability to overwrite withdrawal credentials for new and existing mnemonic

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