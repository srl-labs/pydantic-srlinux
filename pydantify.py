#!/usr/bin/env python3
import argparse
import subprocess
from pathlib import Path

import yaml

# from models import bfd, interfaces
from rich import print

from yang_map import Repo, YangMap


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a pydantify command for a given YANG module"
    )
    parser.add_argument("--module", required=True, help="Module name to process")
    args = parser.parse_args()

    with open("yang_map.yml", "r") as f:
        data = yaml.safe_load(f)

    # Parse YAML data with our YangMap pydantic model
    collection = YangMap(**data)

    # Find the requested module in the map
    yang_module = collection.modules.get(args.module)
    if not yang_module:
        print(f"Module '{args.module}' not found in yang_map.yml.")
        return

    repo: Repo = collection.repo

    # Build the pydantify command
    command = [
        "pydantify",
        f"{repo.path + yang_module.path}",
        f"-p {repo.path}/srlinux-yang-models/srl_nokia",
        f"-p {repo.base_modules['iana']}",
        f"-p {repo.base_modules['ietf']}",
        "-o pydantic_srlinux/models",
        f"-f {args.module.replace('srl_nokia-', '')}.py",  # final name of the model
    ]

    # For each augmented module, add its path as a deviation
    for augmented_module in yang_module.augmented_by:
        module = collection.modules.get(augmented_module)
        if module:
            command.append(f"--deviation {repo.path + module.path}")

    # Create temp directory if it doesn't exist
    temp_dir = Path("./temp")
    temp_dir.mkdir(exist_ok=True)

    # Save command to file
    cmd_file = temp_dir / f".{args.module}.cmd"
    with open(cmd_file, "w") as f:
        f.write(" \\\n  ".join(command))

    # Create models dir if it doesn't exist
    temp_dir = Path("./models")
    temp_dir.mkdir(exist_ok=True)

    # mybfd = bfd.Model(bfd=bfd.BfdContainer())

    # myif = interfaces.Model(
    #     interface=[
    #         interfaces.InterfaceListEntry(
    #             name="ethernet-1/1",
    #             description="hey ac3",
    #             admin_state=interfaces.EnumerationEnum.enable,
    #         )
    #     ]
    # )

    # print(mybfd.model_dump_json(indent=2, exclude_none=True, exclude_unset=True))
    # print(myif.model_dump_json(indent=2, exclude_none=True, exclude_unset=True))

    # now run the generated command
    subprocess.run(" \\\n  ".join(command), check=True, shell=True)


if __name__ == "__main__":
    main()
