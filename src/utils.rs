use eth2_keystore::json_keystore::{HexBytes, Kdf, Pbkdf2, Prf};
use eth2_keystore::{DKLEN, SALT_SIZE};
use rand::Rng;

pub(crate) fn pbkdf2() -> Kdf {
    let salt = rand::thread_rng().gen::<[u8; SALT_SIZE]>();
    Kdf::Pbkdf2(Pbkdf2 {
        dklen: DKLEN,
        c: 262_144,
        prf: Prf::HmacSha256,
        salt: HexBytes::from(salt.to_vec()),
    })
}
