pub(crate) mod operations;

use std::collections::HashMap;

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

pub fn voluntary_exit_message_batch_from_mnemonic(
    mnemonic_phrase: &[u8],
    seed_beacon_mapping: HashMap<u32, u32>,
    epoch: u64,
) -> (Vec<VoluntaryExit>, Vec<VotingKeyMaterial>) {
    let (seed, _) = crate::seed::get_eth2_seed(Some(mnemonic_phrase));

    let mut all_materials = vec![];
    let mut all_messages = vec![];

    for (seed_index, beacon_index) in seed_beacon_mapping {
        let key_materials =
            crate::key_material::seed_to_key_material(&seed, 1, seed_index, None, false, None);

        let key_material = key_materials
            .first()
            .expect("Error deriving key material from mnemonic");
        all_materials.push(key_material.clone());

        let voluntary_exit = VoluntaryExit {
            epoch: Epoch::from(epoch),
            validator_index: beacon_index as u64,
        };
        all_messages.push(voluntary_exit);
    }

    (all_messages, all_materials)
}

pub fn voluntary_exit_message_from_secret_key(
    secret_key_bytes: &[u8],
    validator_beacon_index: u64,
    epoch: u64,
) -> (VoluntaryExit, VotingKeyMaterial) {
    let key_material = VotingKeyMaterial::from_voting_secret_bytes(secret_key_bytes);

    let voluntary_exit = VoluntaryExit {
        epoch: Epoch::from(epoch),
        validator_index: validator_beacon_index,
    };

    (voluntary_exit, key_material)
}

#[cfg(test)]
mod test;
