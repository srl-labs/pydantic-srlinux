#!/usr/bin/env python
import argparse
import os
import re
import subprocess
from typing import Dict, List

import yaml
from pydantic import BaseModel


class YangImport(BaseModel):
    module: str
    prefix: str


class YangAugment(BaseModel):
    node: str


class YangModule(BaseModel):
    name: str
    path: str
    prefix: str
    imports: List[YangImport]
    augments: List[YangAugment]
    augmented_by: List[str] = []


class YangFileCollection(BaseModel):
    modules: Dict[str, YangModule]


def parse_yang_file(file_path: str) -> YangModule:
    with open(file_path, "r") as f:
        content = f.read()

    # Get module name
    module_match = re.search(r"module\s+([^\s{]+)", content)
    module_name = module_match.group(1) if module_match else ""

    # Get prefix
    prefix_match = re.search(r"prefix\s+([^\s;]+)", content)
    prefix = prefix_match.group(1) if prefix_match else ""

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
        path=file_path.replace(os.path.expanduser("~"), "~"),
        prefix=prefix,
        imports=imports,
        augments=augments,
    )


def process_yang_files(directory: str) -> YangFileCollection:
    yang_files: Dict[str, YangModule] = {}

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".yang"):
                file_path = os.path.join(root, file)
                yang_files[file] = parse_yang_file(file_path)

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

    return YangFileCollection(modules=yang_files)


def analyze_import_prefixes(
    collection: YangFileCollection,
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

    # Checkout the specified version
    subprocess.run(["git", "-C", args.dir, "checkout", args.version], check=True)

    yang_directory = os.path.join(
        os.path.expanduser(args.dir), "srlinux-yang-models", "srl_nokia"
    )
    result = process_yang_files(yang_directory)

    # print(result.model_dump_json(indent=2))
    with open("yang_map.yml", "w") as f:
        yaml.dump(result.model_dump(), f)
    # yaml.dump(analyze_import_prefixes(result), sys.stdout)


if __name__ == "__main__":
    main()
