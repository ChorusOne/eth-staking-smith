use eth2_keystore::json_keystore::{HexBytes, Kdf, Pbkdf2, Prf, Scrypt};
use eth2_keystore::{DKLEN, SALT_SIZE};
use ssz::Encode;
use types::PublicKey;

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

/// Returns the withdrawal credentials for a given public key.
///
/// Used for submitting deposits to the Eth1 deposit contract.
pub(crate) fn get_withdrawal_credentials(pubkey: &PublicKey, prefix_byte: u8) -> Vec<u8> {
    let hashed = ethereum_hashing::hash(&pubkey.as_ssz_bytes());
    let mut prefixed = vec![prefix_byte];
    prefixed.extend_from_slice(&hashed[1..]);

    prefixed
}
