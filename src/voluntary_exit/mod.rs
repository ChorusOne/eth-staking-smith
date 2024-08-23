pub(crate) mod operator;

use types::{Epoch, VoluntaryExit};

use crate::key_material::VotingKeyMaterial;

pub fn voluntary_exit_message_from_mnemonic(
    mnemonic_phrase: &[u8],
    validator_seed_index: u64,
    validator_beacon_index: u64,
    epoch: u64,
) -> (VoluntaryExit, VotingKeyMaterial) {
    let (seed, _) = crate::seed::get_eth2_seed(Some(mnemonic_phrase));

    let key_materials = crate::key_material::seed_to_key_material(
        &seed,
        1,
        validator_seed_index as u32,
        None,
        false,
        None,
    );

    let key_material = key_materials
        .first()
        .expect("Error deriving key material from mnemonic");

    let voluntary_exit = VoluntaryExit {
        epoch: Epoch::from(epoch),
        validator_index: validator_beacon_index,
    };

    (voluntary_exit, key_material.clone())
}

#[cfg(test)]
mod test;
