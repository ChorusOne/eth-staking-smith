use eth2_keystore::json_keystore::{HexBytes, Kdf, Pbkdf2, Prf, Scrypt};
use eth2_keystore::{DKLEN, SALT_SIZE};
use regex::Regex;
use types::PublicKeyBytes;

pub(crate) fn pbkdf2() -> Kdf {
    let mut salt = vec![0u8; SALT_SIZE];
    getrandom::getrandom(&mut salt).expect("Failed to generate pbkdf salt using getrandom(2)");
    Kdf::Pbkdf2(Pbkdf2 {
        dklen: DKLEN,
        c: 262_144,
        prf: Prf::HmacSha256,
        salt: HexBytes::from(salt),
    })
}

pub(crate) fn scrypt() -> Kdf {
    let mut salt = vec![0u8; SALT_SIZE];
    getrandom::getrandom(&mut salt).expect("Failed to generate scrypt salt using getrandom(2)");
    Kdf::Scrypt(Scrypt {
        dklen: DKLEN,
        n: 262144,
        p: 1,
        r: 8,
        salt: salt.into(),
    })
}

/// Returns the withdrawal credentials for a given BLS public key.
///
/// Used for submitting deposits to the Eth1 deposit contract.
pub(crate) fn get_withdrawal_credentials(pubkey: &PublicKeyBytes, prefix_byte: u8) -> Vec<u8> {
    let hashed = ethereum_hashing::hash(pubkey.as_serialized());
    let mut prefixed = vec![prefix_byte];
    prefixed.extend_from_slice(&hashed[1..]);

    prefixed
}

/// Given BLS public key, creates 0x0 withdrawal credentials from it
///
/// Used for deriving withdrawal from the validator BLS key pair
pub fn withdrawal_creds_from_pk(withdrawal_pk: &PublicKeyBytes) -> String {
    let withdrawal_creds = get_withdrawal_credentials(withdrawal_pk, 0);
    hex::encode(withdrawal_creds)
}

// Various regexes used for input validation
lazy_static::lazy_static! {
    /// see format of execution address: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#eth1_address_withdrawal_prefix
    pub static ref EXECUTION_ADDR_REGEX: Regex = Regex::new(r"^(0x[a-fA-F0-9]{40})$").unwrap();
    pub static ref EXECUTION_CREDS_REGEX: Regex =
        Regex::new(r"^(0x01[0]{22}[a-fA-F0-9]{40})$").unwrap();
    pub static ref BLS_CREDS_REGEX: Regex = Regex::new(r"^(0x00[a-fA-F0-9]{62})$").unwrap();
}
