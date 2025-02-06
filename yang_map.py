#!/usr/bin/env python
import argparse
import os
import re
import subprocess
from typing import Dict, List

import yaml
from httpx import Response, get
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
    tree_cmd: str  # pyang tree cmd
    yl_cmd: str  # yang lint tree cmd


class Repo(BaseModel):
    version: str
    path: str
    url: str
    base_modules: Dict[str, str] = {}


class Platform(BaseModel):
    features: List[str]


class YangMap(BaseModel):
    modules: Dict[str, YangModule]
    repo: Repo
    platforms: Dict[str, Platform]


DIR_ENV_VAR = "${SRL_YANG_REPO_DIR}"


def parse_yang_file(base_dir, file_path: str, repo: Repo) -> YangModule:
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

    # file path relative to the yang repo dir path
    base_file_path = file_path.replace(base_dir, "")

    return YangModule(
        name=module_name,
        path=base_file_path,
        prefix=Prefix(current=current_prefix, target=target_prefix),
        imports=imports,
        augments=augments,
        tree_cmd=f"pyang -f tree -p {repo.base_modules['srl']} -p {repo.base_modules['ietf']} -p {repo.base_modules['iana']} {DIR_ENV_VAR + base_file_path}",
        yl_cmd=f"yanglint -f tree -p {repo.base_modules['srl']} -p {repo.base_modules['ietf']} -p {repo.base_modules['iana']} -i {DIR_ENV_VAR + base_file_path}",
    )


def process_yang_files(dir: str, repo: Repo) -> Dict[str, YangModule]:
    srl_models_dir = os.path.join(dir, "srlinux-yang-models", "srl_nokia")
    yang_files: Dict[str, YangModule] = {}

    # Go over all yang files in the srl models dir and parse them
    for root, _, files in os.walk(srl_models_dir):
        for file in files:
            if file.endswith(".yang"):
                file_path = os.path.join(root, file)
                yang_module = parse_yang_file(dir, file_path, repo)
                yang_files[yang_module.name] = yang_module

    # Second pass: process augmentations
    for module_file, module in yang_files.items():
        for augment in module.augments:
            prefix_match = re.match(r"/([^:]+):", augment.node)
            if prefix_match:
                augment_prefix = prefix_match.group(1)
                # Find the corresponding module from imports
                for imported_mod in module.imports:
                    if imported_mod.prefix == augment_prefix:
                        augmented_mod = imported_mod.module
                        if augmented_mod in yang_files:
                            # Add the current module to the augmented_by list
                            if (
                                module_file
                                not in yang_files[augmented_mod].augmented_by
                            ):
                                yang_files[augmented_mod].augmented_by.append(
                                    module_file
                                )
                                # add this module as deviation to the tree command
                                # as the penultimate argument
                                py_cmd_parts = yang_files[
                                    augmented_mod
                                ].tree_cmd.split()
                                yl_cmd_parts = yang_files[augmented_mod].yl_cmd.split()

                                # pyang cmd processing
                                py_cmd_parts.insert(-1, "--deviation-module")
                                py_cmd_parts.insert(
                                    -1,
                                    f"{repo.path + yang_files[module_file].path}",
                                )
                                # Join back into a space-separated string
                                yang_files[augmented_mod].tree_cmd = " ".join(
                                    py_cmd_parts
                                )

                                # yanglint cmd processing
                                yl_cmd_parts.append("-i")
                                yl_cmd_parts.append(
                                    f"{repo.path + yang_files[module_file].path}",
                                )
                                # Join back into a space-separated string
                                yang_files[augmented_mod].yl_cmd = " ".join(
                                    yl_cmd_parts
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


def get_platforms(version: str) -> Dict[str, Platform]:
    url = f"https://raw.githubusercontent.com/srl-labs/yang-browser/master/static/releases/{version}/features.txt"
    response: Response = get(url)
    platforms = {}

    for line in response.text.splitlines():
        if line.strip():
            platform, features = line.split(":", 1)
            platform = platform.strip()
            features_list = features.strip().split()
            platforms[platform] = Platform(features=features_list)

    return platforms


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Process YANG files from SR Linux models"
    )
    parser.add_argument("--dir", required=True, help="Path to the repository directory")
    parser.add_argument("--version", required=True, help="Version to checkout")

    args = parser.parse_args()

    dir = os.path.expanduser(args.dir)

    # Checkout the specified version
    subprocess.run(["git", "-C", dir, "checkout", args.version], check=True)

    repo = Repo(
        version=args.version,
        path=DIR_ENV_VAR,
        url=f"https://github.com/nokia/srlinux-yang-models/tree/{args.version}/srlinux-yang-models/srl_nokia/models",
        base_modules={
            "iana": f"{DIR_ENV_VAR}/srlinux-yang-models/iana",
            "ietf": f"{DIR_ENV_VAR}/srlinux-yang-models/ietf",
            "srl": f"{DIR_ENV_VAR}/srlinux-yang-models/srl_nokia",
        },
    )

    yang_modules = process_yang_files(dir, repo)

    platforms: Dict[str, Platform] = get_platforms(version=args.version)

    map = YangMap(
        modules=yang_modules,
        repo=repo,
        platforms=platforms,
    )

    with open("yang_map.yml", "w") as f:
        yaml.dump(map.model_dump(), f, width=float("inf"))


if __name__ == "__main__":
    main()
