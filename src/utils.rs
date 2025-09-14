use eth2_keystore::json_keystore::{HexBytes, Kdf, Pbkdf2, Prf, Scrypt};
use eth2_keystore::{DKLEN, SALT_SIZE};
use regex::Regex;
use types::PublicKeyBytes;

pub(crate) fn pbkdf2() -> Kdf {
    let mut salt = vec![0u8; SALT_SIZE];
    getrandom::fill(&mut salt).expect("Failed to generate pbkdf salt using getrandom(2)");
    Kdf::Pbkdf2(Pbkdf2 {
        dklen: DKLEN,
        c: 262_144,
        prf: Prf::HmacSha256,
        salt: HexBytes::from(salt),
    })
}

pub(crate) fn scrypt() -> Kdf {
    let mut salt = vec![0u8; SALT_SIZE];
    getrandom::fill(&mut salt).expect("Failed to generate scrypt salt using getrandom(2)");
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

/// Creates 0x02 compounding withdrawal credentials from BLS public key (EIP-7251)
///
/// Used for type 2 validators that support compounding rewards up to 2048 ETH
pub fn compounding_withdrawal_creds_from_pk(withdrawal_pk: &PublicKeyBytes) -> String {
    let withdrawal_creds = get_withdrawal_credentials(withdrawal_pk, 2);
    hex::encode(withdrawal_creds)
}

/// Validates deposit amount according to Ethereum staking rules
///
/// Post-Pectra (EIP-7251): 32 ETH to 2048 ETH for compounding validators
/// Pre-Pectra: Only 32 ETH allowed
pub fn validate_deposit_amount(amount_gwei: u64, is_compounding: bool) -> Result<(), String> {
    const MIN_DEPOSIT_GWEI: u64 = 32_000_000_000; // 32 ETH
    const MAX_EFFECTIVE_BALANCE: u64 = 2_048_000_000_000; // 2048 ETH

    if amount_gwei < MIN_DEPOSIT_GWEI {
        return Err(format!(
            "Deposit amount must be at least 32 ETH (got {} Gwei)",
            amount_gwei
        ));
    }

    if is_compounding {
        if amount_gwei > MAX_EFFECTIVE_BALANCE {
            return Err(format!(
                "Compounding validator deposit amount cannot exceed 2048 ETH (got {} Gwei)",
                amount_gwei
            ));
        }
    } else if amount_gwei != MIN_DEPOSIT_GWEI {
        return Err(format!(
            "Non-compounding validator deposit amount must be exactly 32 ETH (got {} Gwei)",
            amount_gwei
        ));
    }

    Ok(())
}

/// Determines if withdrawal credentials indicate a compounding validator (0x02 prefix)
pub fn is_compounding_withdrawal_credentials(withdrawal_credentials: &str) -> bool {
    let creds = if let Some(stripped) = withdrawal_credentials.strip_prefix("0x") {
        stripped
    } else {
        withdrawal_credentials
    };
    creds.starts_with("02")
}

// Various regexes used for input validation
lazy_static::lazy_static! {
    /// see format of execution address: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/validator.md#eth1_address_withdrawal_prefix
    pub static ref EXECUTION_ADDR_REGEX: Regex = Regex::new(r"^(0x[a-fA-F0-9]{40})$").unwrap();
    pub static ref EXECUTION_CREDS_REGEX: Regex =
        Regex::new(r"^(0x01[0]{22}[a-fA-F0-9]{40})$").unwrap();
    pub static ref BLS_CREDS_REGEX: Regex = Regex::new(r"^(0x00[a-fA-F0-9]{62})$").unwrap();
    /// EIP-7251 compounding withdrawal credentials pattern
    pub static ref COMPOUNDING_CREDS_REGEX: Regex = Regex::new(r"^(0x02[a-fA-F0-9]{62})$").unwrap();
}
