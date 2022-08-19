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
