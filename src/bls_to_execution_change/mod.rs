pub(crate) mod operations;

use types::{Address, BlsToExecutionChange};

use crate::key_material::VotingKeyMaterial;

pub fn bls_execution_change_from_mnemonic(
    mnemonic_phrase: &[u8],
    validator_start_index: u64,
    validator_beacon_index: u64,
    execution_address: &str,
) -> (BlsToExecutionChange, VotingKeyMaterial) {
    let (seed, _) = crate::seed::get_eth2_seed(Some(mnemonic_phrase));

    if !crate::utils::EXECUTION_ADDR_REGEX.is_match(execution_address) {
        panic!(
            "Invalid execution address: Please pass in a valid execution address with the correct format"
        );
    }

    let execution_address = Address::from_slice(
        hex::decode(
            execution_address
                .strip_prefix("0x")
                .expect("0x prefix is required for execution_address"),
        )
        .expect("Invalid hex passed as execution_address")
        .as_slice(),
    );

    let key_materials = crate::key_material::seed_to_key_material(
        &seed,
        1,
        validator_start_index as u32,
        None,
        true,
        None,
    );

    let key_material = key_materials
        .first()
        .expect("Error deriving key material from mnemonic");

    let key_pair = key_material.withdrawal_keypair.clone().unwrap();

    let bls_to_execution_change = BlsToExecutionChange {
        validator_index: validator_beacon_index,
        from_bls_pubkey: key_pair.pk.into(),
        to_execution_address: execution_address,
    };

    (bls_to_execution_change, key_material.clone())
}

#[cfg(test)]
mod test;
