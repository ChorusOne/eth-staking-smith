use eth2_hashing::hash;
use eth2_keystore::json_keystore::{HexBytes, Kdf, Pbkdf2, Prf};
use eth2_keystore::{DKLEN, SALT_SIZE};
use rand::Rng;
use ssz::Encode;
use types::PublicKey;

pub(crate) fn pbkdf2() -> Kdf {
    let salt = rand::thread_rng().gen::<[u8; SALT_SIZE]>();
    Kdf::Pbkdf2(Pbkdf2 {
        dklen: DKLEN,
        c: 262_144,
        prf: Prf::HmacSha256,
        salt: HexBytes::from(salt.to_vec()),
    })
}

/// Returns the withdrawal credentials for a given public key.
///
/// Used for submitting deposits to the Eth1 deposit contract.
pub(crate) fn get_withdrawal_credentials(pubkey: &PublicKey, prefix_byte: u8) -> Vec<u8> {
    let hashed = hash(&pubkey.as_ssz_bytes());
    let mut prefixed = vec![prefix_byte];
    prefixed.extend_from_slice(&hashed[1..]);

    prefixed
}
