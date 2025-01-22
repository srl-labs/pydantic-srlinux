import os
import re
import sys
from typing import Dict, List, Optional

import yaml
from pydantic import BaseModel
from rich import print


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
    p = "~/projects/nokia/srlinux-yang-models/srlinux-yang-models/srl_nokia"
    yang_directory = os.path.expanduser(p)
    # yang_directory = (
    #     "/home/romandodin/projects/nokia/srlinux-yang-models/srlinux-yang-models/test"
    # )
    result = process_yang_files(yang_directory)

    # print(result.model_dump_json(indent=2))
    # yaml.dump(result.model_dump(), sys.stdout)
    yaml.dump(analyze_import_prefixes(result), sys.stdout)


if __name__ == "__main__":
    main()
