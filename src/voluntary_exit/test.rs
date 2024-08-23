use crate::{chain_spec::validators_root_and_spec, networks::SupportedNetworks};

const PHRASE: &str = "entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup";

#[test]
fn it_generates_presigned_exit_message() {
    let (genesis_validators_root, spec) =
        validators_root_and_spec(Some(SupportedNetworks::Holesky), None);

    let (voluntary_exit, key_material) =
        crate::voluntary_exit::voluntary_exit_message_from_mnemonic(
            PHRASE.as_bytes(),
            0,
            100,
            73682,
        );

    let signed_voluntary_exit =
        voluntary_exit.sign(&key_material.keypair.sk, genesis_validators_root, &spec);

    assert_eq!(100, signed_voluntary_exit.message.validator_index);
    assert_eq!(73682, signed_voluntary_exit.message.epoch.as_u64());
    assert_eq!("0xa418543c8bdc266e00a45d7409386fffe02ad9ce3c1e707d562b38f7160966567602c518f6615edc8ecd964b978837f30a742c535dafc33137833b3aa6c30f4fecf37449de405ed50d8e436f21c6f58c0a48407037b1985507c3221ce53ba213", signed_voluntary_exit.signature.to_string());
}
