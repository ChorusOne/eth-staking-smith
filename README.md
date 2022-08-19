eth-staking-smith
================

# Introduction

Command-line tool to facilitate key and deposit data generation for ethereum proof-of-stake validators.

Why we need yet another keystore / deposit tool:

1. eth-staking-smith written in Rust
2. ability to use as a library to automate key and deposit data generation
3. opt-out of writing to filesystem for better security

# Usage

```
cargo build
```

## Existing mnemonic 

Regenerate key and deposit data with existing mnemonic:

```
./target/debug/eth-staking-smith existing-mnemonic --help
```

### Example command:

```
./target/debug/eth-staking-smith existing-mnemonic --chain mainnet --keystore_password test --mnemonic "entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup" --num_validators 1 --withdrawal_address "0100000000000000000000000000000000000000000000000000000000000001"
```

<!-- 
required to cater for our use case: 

1. generate N validators with new mnemonic
2. regenerate N validators with new mnemonic
3. regenerate N validators with existing mnemonic specifying eth1 or eth2 withdrawal address 

-->

# Implementation Details 
To avoid heavy lifting, we're interfacing [Lighthouse account manager](https://github.com/sigp/lighthouse/blob/stable/account_manager), but optimizing it in a way so all operations are done in memory and key material is never written to filesystem during the generation to cater for our use case.

# Glossary (WIP)

| Term      | Description |
| ----------- | ----------- |
| Wallet      | Interface to manage accounts       |
| Account   | public/private keypair that points to your funds        |
| keystore file   | encrypted version of your private key in JSON funds        |
| mnemonic phrase / seed phrase / seed words   | 12 or 24 word phrase to access infinite number of accounts, used to derive multiple private keys        |
| seed   | input given to derive a private key (should be truly random!)        |
| wallet password   |        |
| decryption key   |    used to encrypt/decrypt keystore file    |

# Getting involved

## Major tasks tdb for first iteration:
- [X] Create eth2 Wallet from Mnemonic
- [X] Create validator Keystore from eth2 Wallet
- [X] Create eth1 deposit data from validator Keystore
- [X] Create N validators from Mnemonic
- [X] create basic cli interface to cater for our use case

## Upcoming 
- [ ] extend cli interface to add new-mnemonic command
- [ ] add negative test cases
- [ ] add e2e tests 
- [ ] (for funnsies) progress bar