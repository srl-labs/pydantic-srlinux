#!/usr/bin/env python3
from typing import List
import sys
import argparse
import subprocess
from pathlib import Path

import yaml

# from models import bfd, interfaces
from rich import print

from yang_map import Repo, YangMap
from pydantify.main import main as pydantify_main


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
    relay_args: List[str] = []
    relay_args.append(f"{repo.path + yang_module.path}")
    relay_args.extend(["-p", repo.path +"/srlinux-yang-models/srl_nokia"])
    relay_args.extend(["-p", repo.base_modules['iana']])
    relay_args.extend(["-p", repo.base_modules['ietf']])

    relay_args.extend(["-o" , "pydantic_srlinux/models"])
    relay_args.extend(["-f", args.module.replace('srl_nokia-', '') +".py"])


    # For each augmented module, add its path as a deviation
    for augmented_module in yang_module.augmented_by:
        module = collection.modules.get(augmented_module)
        if module:
            relay_args.extend(["--deviation", repo.path + module.path])

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
    sys.argv[1:] = relay_args
    pydantify_main()


if __name__ == "__main__":
    main()
