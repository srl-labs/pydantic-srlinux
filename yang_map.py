#!/usr/bin/env python
import argparse
import os
import re
import subprocess
from typing import Dict, List

import yaml
from pydantic import BaseModel


class Prefix(BaseModel):
    current: str
    target: str


class YangImport(BaseModel):
    module: str
    prefix: str


class YangAugment(BaseModel):
    node: str


class YangModule(BaseModel):
    name: str
    path: str
    prefix: Prefix
    imports: List[YangImport]
    augments: List[YangAugment]
    augmented_by: List[str] = []


class Repo(BaseModel):
    version: str
    path: str
    url: str


class YangMap(BaseModel):
    modules: Dict[str, YangModule]
    repo: Repo


def parse_yang_file(base_dir, file_path: str) -> YangModule:
    with open(file_path, "r") as f:
        content = f.read()

    # Get module name
    module_match = re.search(r"module\s+([^\s{]+)", content)
    module_name = module_match.group(1) if module_match else ""

    # Get prefix
    prefix_match = re.search(r"prefix\s+([^\s;]+)", content)
    current_prefix = prefix_match.group(1) if prefix_match else ""
    # target prefix should be a module name without .yang and with srl_nokia substituted with srl
    target_prefix = module_name.replace(".yang", "").replace("srl_nokia", "srl")

    # Get imports
    imports: List[YangImport] = []
    import_matches = re.finditer(
        r"import\s+([^\s{]+)\s*{[^}]*prefix\s+([^\s;]+)", content
    )
    for match in import_matches:
        imports.append(YangImport(module=match.group(1), prefix=match.group(2)))

    # Get augments
    augments: List[YangAugment] = []
    augment_matches = re.finditer(r'augment\s+"([^"]+)"', content)
    for match in augment_matches:
        augments.append(YangAugment(node=match.group(1).strip()))

    return YangModule(
        name=module_name,
        path=file_path.replace(
            base_dir, ""
        ),  # make module paths relative to the base dir
        prefix=Prefix(current=current_prefix, target=target_prefix),
        imports=imports,
        augments=augments,
    )


def process_yang_files(dir: str) -> Dict[str, YangModule]:
    srl_models_dir = os.path.join(dir, "srlinux-yang-models", "srl_nokia")
    yang_files: Dict[str, YangModule] = {}

    # Go over all yang files in the srl models dir and parse them
    for root, _, files in os.walk(srl_models_dir):
        for file in files:
            if file.endswith(".yang"):
                file_path = os.path.join(root, file)
                yang_module = parse_yang_file(dir, file_path)
                yang_files[yang_module.name] = yang_module

    # Second pass: process augmentations
    for module_file, module in yang_files.items():
        for augment in module.augments:
            prefix_match = re.match(r"/([^:]+):", augment.node)
            if prefix_match:
                augment_prefix = prefix_match.group(1)
                # Find the corresponding module from imports
                for imp in module.imports:
                    if imp.prefix == augment_prefix:
                        augmented_module = imp.module + ".yang"
                        if augmented_module in yang_files:
                            # Add the current module to the augmented_by list
                            if (
                                module_file
                                not in yang_files[augmented_module].augmented_by
                            ):
                                yang_files[augmented_module].augmented_by.append(
                                    module_file
                                )
                        break

    return yang_files


def analyze_import_prefixes(
    collection: YangMap,
) -> Dict[str, Dict[str, int]]:
    """Returns a dictionary of module names to a dictionary of prefixes to their counts.
    Used to display what modules are imported with what prefixes.
    """
    module_prefix_counts: Dict[str, Dict[str, int]] = {}

    for module in collection.modules.values():
        for yang_import in module.imports:
            if yang_import.module not in module_prefix_counts:
                module_prefix_counts[yang_import.module] = {}

            prefix_counts = module_prefix_counts[yang_import.module]
            prefix_counts[yang_import.prefix] = (
                prefix_counts.get(yang_import.prefix, 0) + 1
            )

    return module_prefix_counts


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Process YANG files from SR Linux models"
    )
    parser.add_argument("--dir", required=True, help="Path to the repository directory")
    parser.add_argument("--version", required=True, help="Version to checkout")

    args = parser.parse_args()

    dir = os.path.expanduser(args.dir)
    # non expanded dir is used in the map file to avoid disclosure of the home directory
    non_expanded_dir = dir.replace(os.path.expanduser("~"), "~")

    # Checkout the specified version
    subprocess.run(["git", "-C", dir, "checkout", args.version], check=True)

    yang_files = process_yang_files(dir)

    map = YangMap(
        modules=yang_files,
        repo=Repo(
            version=args.version,
            path=non_expanded_dir,
            url=f"https://github.com/nokia/srlinux-yang-models/tree/{args.version}/srlinux-yang-models/srl_nokia/models",
        ),
    )

    # print(result.model_dump_json(indent=2))
    with open("yang_map.yml", "w") as f:
        yaml.dump(map.model_dump(), f)
    # yaml.dump(analyze_import_prefixes(result), sys.stdout)


if __name__ == "__main__":
    main()
