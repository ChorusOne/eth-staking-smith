use std::str::FromStr;

use crate::{key_material, seed::get_eth2_seed, utils::get_withdrawal_credentials};
use lazy_static::lazy_static;
use regex::Regex;
use ssz_rs::prelude::*;
use types::{Hash256, Keypair, PublicKey, SecretKey, Signature};

const DOMAIN_LEN: usize = 32;
const DOMAIN_TYPE_LEN: usize = 4;
const BLS_PUBKEY_LEN: usize = 96;
const EXECUTION_ADDR_LEN: usize = 40;
type DomainType = Vector<u8, DOMAIN_TYPE_LEN>;
type Domain = Vector<u8, DOMAIN_LEN>;
type Version = Vector<u8, 4>;
type BLSPubkey = Vector<u8, BLS_PUBKEY_LEN>;
type ExecutionAddress = Vector<u8, EXECUTION_ADDR_LEN>;

lazy_static! {
    static ref DOMAIN_BLS_TO_EXECUTION_CHANGE: DomainType =
        Vector::<u8, DOMAIN_TYPE_LEN>::deserialize(&[0x0A, 0, 0, 0])
            .expect("failed to deserialize");
}

#[derive(SimpleSerialize, Default)]
pub struct ForkData {
    current_version: Version,
    genesis_validators_root: Node,
}

#[derive(SimpleSerialize, Default)]
pub struct SigningData {
    object_root: Node,
    domain: Domain,
}

#[derive(Clone)]
pub struct BLSToExecutionRequest {
    validator_index: u32,
    bls_keys: Keypair,
    to_execution_address: ExecutionAddress,
}

#[derive(SimpleSerialize, Default, Clone, Debug)]
pub struct BLSToExecutionChange {
    validator_index: u32,
    from_bls_pubkey: BLSPubkey,
    to_execution_address: ExecutionAddress,
}

#[derive(Debug, Clone)]
pub struct SignedBLSToExecutionChange {
    message: BLSToExecutionChange,
    signature: Signature,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BLSToExecutionChangeExport {
    pub validator_index: u32,
    pub from_bls_pubkey: String,
    pub to_execution_address: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedBLSToExecutionChangeExport {
    pub message: BLSToExecutionChangeExport,
    pub signature: String,
}

impl SignedBLSToExecutionChange {
    pub fn validate(self, from_bls_withdrawal_credentials: &str, to_execution_address: &str) {
        // execution address is same as input
        let execution_address = std::str::from_utf8(&self.message.to_execution_address).unwrap();
        assert_eq!(to_execution_address, format!("0x{}", execution_address));

        // withdrawal credentials are the same as input
        let withdrawal_pubkey = std::str::from_utf8(&self.message.from_bls_pubkey).unwrap();
        let withdrawal_pubkey = PublicKey::from_str(&format!("0x{}", withdrawal_pubkey)).unwrap();

        let withdrawal_credentials = hex::encode(get_withdrawal_credentials(&withdrawal_pubkey, 0));
        let withdrawal_credentials =
            std::str::from_utf8(withdrawal_credentials.as_bytes()).unwrap();

        assert_eq!(
            from_bls_withdrawal_credentials,
            format!("0x{}", withdrawal_credentials)
        );

        // verify signature

        // FIXME: fork version hardcoded for mainnet
        let fork_version = Vector::<u8, DOMAIN_TYPE_LEN>::deserialize(&[0x03, 0, 0, 0])
            .expect("failed to deserialize");

        // FIXME: genesis_validators_root hardcoded
        let domain = compute_domain(
            &DOMAIN_BLS_TO_EXECUTION_CHANGE,
            fork_version,
            Node::from_bytes(Hash256::zero().0),
        )
        .expect("could not compute domain");

        let signing_root = compute_signing_root(self.message.clone(), domain)
            .expect("could not compute signing root");

        self.signature.verify(
            &withdrawal_pubkey,
            Hash256::from_slice(signing_root.as_bytes()),
        );
    }

    pub fn export(&self) -> SignedBLSToExecutionChangeExport {
        let withdrawal_pubkey = std::str::from_utf8(&self.message.from_bls_pubkey).unwrap();
        let withdrawal_pubkey = PublicKey::from_str(&format!("0x{}", withdrawal_pubkey)).unwrap();

        let withdrawal_credentials = hex::encode(get_withdrawal_credentials(&withdrawal_pubkey, 0));
        let withdrawal_credentials =
            std::str::from_utf8(withdrawal_credentials.as_bytes()).unwrap();

        let to_execution_address = std::str::from_utf8(&self.message.to_execution_address).unwrap();

        SignedBLSToExecutionChangeExport {
            message: BLSToExecutionChangeExport {
                validator_index: self.message.validator_index,
                from_bls_pubkey: format!("0x{}", withdrawal_credentials),
                to_execution_address: format!("0x{}", to_execution_address),
            },
            signature: self.signature.to_string(),
        }
    }
}

impl BLSToExecutionRequest {
    pub fn new(
        mnemonic_phrase: &[u8],
        validator_start_index: u32,
        execution_address: &str,
    ) -> Self {
        let (seed, _) = get_eth2_seed(Some(mnemonic_phrase));

        let execution_addr_regex: Regex = Regex::new(r"^(0x[a-fA-F0-9]{40})$").unwrap();

        if !execution_addr_regex.is_match(execution_address) {
            panic!(
                "Invalid execution address: Please pass in a valid execution address with the correct format"
            );
        }

        let execution_address = Vector::<u8, EXECUTION_ADDR_LEN>::deserialize(
            execution_address.strip_prefix("0x").unwrap().as_bytes(),
        )
        .expect("failed to deserialize");

        let key_materials =
            key_material::seed_to_key_material(&seed, 1, validator_start_index, None, true, None);

        let key_material = key_materials
            .get(0)
            .expect("Error deriving key material from mnemonic");

        BLSToExecutionRequest {
            validator_index: validator_start_index,
            bls_keys: key_material
                .withdrawal_keypair
                .clone()
                .expect("Error deriving key material from mnemonic"),
            to_execution_address: execution_address,
        }
    }

    pub fn sign(self) -> SignedBLSToExecutionChange {
        let withdrawal_pubkey = Vector::<u8, BLS_PUBKEY_LEN>::deserialize(
            self.bls_keys
                .pk
                .to_string()
                .strip_prefix("0x")
                .unwrap()
                .as_bytes(),
        )
        .expect("failed to deserialize");

        let message = BLSToExecutionChange {
            validator_index: self.validator_index,
            from_bls_pubkey: withdrawal_pubkey,
            to_execution_address: self.to_execution_address,
        };

        let secret_key = self.bls_keys.sk.serialize();

        let withdrawal_privkey = secret_key.as_bytes();

        generate_signed_bls_to_execution_change(message, withdrawal_privkey)
            .expect("error generating signing bls to execution change")
    }
}

fn generate_signed_bls_to_execution_change(
    message: BLSToExecutionChange,
    secret_key: &[u8],
) -> Result<SignedBLSToExecutionChange, Box<dyn std::error::Error>> {
    // FIXME: hardcoded for mainnet
    let fork_version = Vector::<u8, DOMAIN_TYPE_LEN>::deserialize(&[0x03, 0, 0, 0])
        .expect("failed to deserialize");

    // FIXME: hardcoded for mainnet
    let domain = compute_domain(
        &DOMAIN_BLS_TO_EXECUTION_CHANGE,
        fork_version,
        Node::from_bytes(Hash256::zero().0),
    )?;

    let signing_root = compute_signing_root(message.clone(), domain)?;

    let signature = sign(secret_key, signing_root)?;

    Ok(SignedBLSToExecutionChange { message, signature })
}

/// based on https://github.com/ethereum/consensus-specs/blob/02b32100ed26c3c7a4a44f41b932437859487fd2/specs/phase0/beacon-chain.md#compute_domain
fn compute_domain(
    domain_type: &DomainType,
    fork_version: Version,
    genesis_validators_root: Node,
) -> Result<Domain, MerkleizationError> {
    let fork_data_root = compute_fork_data_root(fork_version, genesis_validators_root)?;
    let mut bytes = Vec::new();
    domain_type.serialize(&mut bytes)?;
    fork_data_root.serialize(&mut bytes)?;
    Ok(Vector::deserialize(&bytes[0..DOMAIN_LEN]).expect("invalid domain data"))
}

/// based on https://github.com/ethereum/consensus-specs/blob/02b32100ed26c3c7a4a44f41b932437859487fd2/specs/phase0/beacon-chain.md#compute_fork_data_root
fn compute_fork_data_root(
    current_version: Version,
    genesis_validators_root: Node,
) -> Result<Node, MerkleizationError> {
    ForkData {
        current_version,
        genesis_validators_root,
    }
    .hash_tree_root()
}

/// based on https://github.com/ethereum/consensus-specs/blob/02b32100ed26c3c7a4a44f41b932437859487fd2/specs/phase0/beacon-chain.md#compute_signing_root
pub fn compute_signing_root<T: SimpleSerialize>(
    mut ssz_object: T,
    domain: Domain,
) -> Result<Node, MerkleizationError> {
    SigningData {
        object_root: ssz_object.hash_tree_root()?,
        domain,
    }
    .hash_tree_root()
}

/// based on https://github.com/ethereum/consensus-specs/blob/02b32100ed26c3c7a4a44f41b932437859487fd2/specs/phase0/beacon-chain.md#bls-signatures
fn sign(secret_key: &[u8], msg: Node) -> Result<Signature, Box<dyn std::error::Error>> {
    let secret_key = SecretKey::deserialize(secret_key).expect("couldn't load the key");
    let message = Hash256::from_slice(msg.as_bytes());
    Ok(secret_key.sign(message))
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use types::{Hash256, PublicKey};

    use crate::utils;

    use super::BLSToExecutionRequest;

    const EXECUTION_WITHDRAWAL_ADDRESS: &str = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F";
    const PHRASE: &str = "entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup";

    #[test]
    fn it_generates_signed_bls_to_execution_change() {
        // Keys asserted here are generated with the staking-deposit cli
        // ./deposit existing-mnemonic --keystore_password testtest

        // Please enter your mnemonic separated by spaces (" "): entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup
        // Enter the index (key number) you wish to start generating more keys from. For example, if you've generated 4 keys in the past, you'd enter 4 here. [0]: 0
        // Please choose how many new validators you wish to run: 1
        // Please choose the (mainnet or testnet) network/chain name ['mainnet', 'prater', 'kintsugi', 'kiln', 'minimal']:  [mainnet]: minimal

        fn withdrawal_creds_from_pk(withdrawal_pk: &PublicKey) -> String {
            let withdrawal_creds = utils::get_withdrawal_credentials(&withdrawal_pk, 0);
            let credentials_hash = Hash256::from_slice(&withdrawal_creds);
            hex::encode(&credentials_hash.as_bytes())
        }

        let bls_to_execution_change =
            BLSToExecutionRequest::new(PHRASE.as_bytes(), 0, EXECUTION_WITHDRAWAL_ADDRESS);
        let signed_bls_to_execution_change = bls_to_execution_change.sign();

        // format generated fields for assertion
        let to_execution_address =
            std::str::from_utf8(&signed_bls_to_execution_change.message.to_execution_address)
                .unwrap();

        let withdrawal_pub_key_str =
            std::str::from_utf8(&signed_bls_to_execution_change.message.from_bls_pubkey).unwrap();
        let withdrawal_pub_key =
            PublicKey::from_str(&format!("0x{}", withdrawal_pub_key_str)).unwrap();

        assert_eq!(
            EXECUTION_WITHDRAWAL_ADDRESS,
            format!("0x{}", to_execution_address)
        );
        assert_eq!(
            "00e078f11bc1454244bdf9f63a3b997815f081dd6630204186d4c9627a2942f7",
            withdrawal_creds_from_pk(&withdrawal_pub_key)
        );
    }
}
