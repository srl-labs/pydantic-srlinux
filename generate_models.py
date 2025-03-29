#!/usr/bin/env python3
import argparse
import os
import subprocess
import sys
from pathlib import Path
from posixpath import expandvars
from typing import List

import yaml
from pydantify.main import main as pydantify_main
from rich import print

from yang_map import Repo, YangMap


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a pydantify command for a given YANG module"
    )
    parser.add_argument(
        "--module", required=True, help="Module name to process", type=str
    )
    parser.add_argument(
        "--platform",
        required=False,
        help="Platform name to determine enabled features (e.g. 7250-IXR-X1B). If unspecified, all features will be enabled",
        type=str,
    )
    parser.add_argument(
        "--data-type",
        action="store",
        dest="data_type",
        choices=["config", "state"],
        help="Limit output to config or state only. Default is config and state combined.",
        default=None,
    )
    args = parser.parse_args()

    # exit if ${SRL_REPO_PATH} is not set
    if not os.environ.get("SRL_YANG_REPO_DIR"):
        print(
            "SRL_YANG_REPO_DIR env var must be set and point to a path where the srlinux-yang-models repo has been cloned"
        )
        sys.exit(1)

    with open("yang_map.yml", "r") as f:
        data = yaml.safe_load(f)

    # Parse YAML data with our YangMap pydantic model
    collection = YangMap(**data)

    # Find the requested module in the map
    yang_module = collection.modules.get(args.module)
    if not yang_module:
        print(f"Module '{args.module}' not found in yang_map.yml")
        return

    repo: Repo = collection.repo
    expanded_repo_path = expandvars(repo.path)

    # Checkout the specified version
    subprocess.run(
        ["git", "-C", expandvars(repo.path), "checkout", repo.version],
        check=True,
    )

    # Build the pydantify command
    relay_args: List[str] = []
    relay_args.extend(["pydantify"])
    relay_args.append(f"{expanded_repo_path + yang_module.path}")
    relay_args.extend(["-p", expanded_repo_path + "/srlinux-yang-models/srl_nokia"])
    relay_args.extend(["-p", expandvars(repo.base_modules["iana"])])
    relay_args.extend(["-p", expandvars(repo.base_modules["ietf"])])
    if args.data_type:
        relay_args.extend(["--data-type", args.data_type])

    relay_args.extend(["-o", "pydantic_srlinux/models"])
    relay_args.extend(
        ["-f", args.module.replace("srl_nokia-", "").replace("-", "_") + ".py"]
    )

    if args.platform:
        platform = collection.platforms.get(args.platform)
        if not platform:
            print(f"Platform '{args.platform}' not found in yang_map.yml")
            return
        features_string = ""
        for feature in platform.features:
            features_string += feature + ","
        relay_args.extend(["-F", f"srl_nokia-features:{features_string}"])

    # For each augmented module, add its path as a deviation
    for augmented_module in yang_module.augmented_by:
        module = collection.modules.get(augmented_module)
        if module:
            relay_args.extend(["--deviation-module", expanded_repo_path + module.path])

    # Create temp directory if it doesn't exist
    temp_dir = Path("./temp")
    temp_dir.mkdir(exist_ok=True)

    # Save command to file
    cmd_file = temp_dir / f".{args.module}.cmd"
    with open(cmd_file, "w") as f:
        f.write(" \\\n  ".join(relay_args))

    # Create models dir if it doesn't exist
    temp_dir = Path("./models")
    temp_dir.mkdir(exist_ok=True)

    # now run the generated command
    sys.argv = relay_args
    pydantify_main()


if __name__ == "__main__":
    main()
