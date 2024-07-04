#!/usr/bin/env python3

#
# This script takes JSON output of `eth-staking-smith` into stdin,
# and produces folder with deposit data and keystore files in the given
# location.
#
# Caveat: keystore_password should be specified before generating.
#

import argparse
import json
import logging
import pathlib
import sys
import time


logger = logging.getLogger(__name__)
parser = argparse.ArgumentParser("Generate eth validator keys folder")
parser.add_argument(
    "output_folder",
    default=pathlib.Path("validator_keys/"),
    nargs="?",
    help="Folder where to store deposit data",
)


def main():
    args = parser.parse_args()
    base_path = args.output_folder
    if type(base_path) == str:
        base_path = pathlib.Path(base_path)
    assert base_path.exists(), "Output folder must exist"
    inp = sys.stdin.read()
    assert inp, "Should have value at standard input"
    try:
        validators = json.loads(inp)
    except (KeyError, ValueError) as exc:
        logger.exception("Got invalid json input")
    else:
        assert validators, "Should have non-empty JSON value passed"
        assert (
            "keystores" in validators
        ), "Should have non-empty keystores in eth-staking-smith output"
        deposit_datas = validators["deposit_data"]
        num_validators = len(deposit_datas)
        print(f"Exporting {num_validators} keystores to {base_path}")
        # Set path as EIP-2334 format
        # https://eips.ethereum.org/EIPS/eip-2334
        for idx, keystore in enumerate(validators["keystores"]):
            ts = int(time.time())
            purpose = "12381"
            coin_type = "3600"
            account = str(idx)
            withdrawal_key_path = f"m/{purpose}/{coin_type}/{account}/0"
            signing_key_path = f"{withdrawal_key_path}/0"
            file_path = signing_key_path.replace("/", "_")
            filename = f"keystore-{file_path}-{ts}.json"
            with open(base_path / filename, "w") as fl:
                fl.write(json.dumps(keystore))

        with open(base_path / f"deposit_data-{ts}.json", "w") as fl:
            fl.write(json.dumps(deposit_datas))


if __name__ == "__main__":
    logging.basicConfig(stream=sys.stdout, level=logging.WARN)
    main()
