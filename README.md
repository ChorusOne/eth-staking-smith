eth-staking-smith
================

Command-line tool to facilitate key and deposit data generation for ethereum proof-of-stake validators.

Why we need yet another keystore / deposit tool:

1. eth-staking-smith written in Rust
2. ability to use as a library to automate key and deposit data generation
3. opt-out of writing to filesystem for better security

# Usage

<!-- 
required to cater for our use case: 

1. generate N validators with new mnemonic
2. regenerate N validators with new mnemonic
3. regenerate N validators with existing mnemonic specifying eth1 or eth2 withdrawal address 

-->

# Implementation Details 
To avoid heavy lifting, we're interfacing [Lighthouse account manager](https://github.com/sigp/lighthouse/blob/stable/account_manager), but optimizing it in a way so all operations are done in memory and key material is never written to filesystem during the generation to cater for our use case.

# Glossary

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
- [ ] Create eth2 Wallet from Mnemonic
- [ ] Create validator Keystore from eth2 Wallet
- [ ] Create eth1 deposit data from validator Keystore
- [ ] Create N validators from Mnemonic
- [ ] create cli interface to cater for our use case

## Upcoming 
- [ ] extend cli interface