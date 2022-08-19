use eth2_keystore::json_keystore::{HexBytes, Kdf, Pbkdf2, Prf};
use eth2_keystore::{DKLEN, SALT_SIZE};
use rand::{distributions::Alphanumeric, Rng};

lazy_static! {
    /// Generate temporary random password of 32 bytes.
    /// This password is only used to encrypt Wallet in memory and dropped
    /// after the program concludes.
    pub(crate) static ref WALLET_PASSWORD: Vec<u8> = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(13)
        .collect();
}

/// Convert random password into byte slices.
pub(crate) fn wallet_password_bytes() -> [u8; 13] {
    WALLET_PASSWORD.as_slice().try_into().unwrap()
}

pub(crate) fn pbkdf2() -> Kdf {
    let salt = rand::thread_rng().gen::<[u8; SALT_SIZE]>();
    Kdf::Pbkdf2(Pbkdf2 {
        dklen: DKLEN,
        c: 262_144,
        prf: Prf::HmacSha256,
        salt: HexBytes::from(salt.to_vec()),
    })
}
