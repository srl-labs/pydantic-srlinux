import os
import re
from typing import Dict, List

def parse_yang_file(file_path: str) -> Dict:
    result = {}
    with open(file_path, 'r') as f:
        content = f.read()
        
    # Get module name
    module_match = re.search(r'module\s+([^\s{]+)', content)
    if module_match:
        result['module_name'] = module_match.group(1)
    
    # Get prefix
    prefix_match = re.search(r'prefix\s+([^\s;]+)', content)
    if prefix_match:
        result['prefix'] = prefix_match.group(1)
    
    # Get imports
    imports = []
    import_matches = re.finditer(r'import\s+([^\s{]+)\s*{[^}]*prefix\s+([^\s;]+)', content)
    for match in import_matches:
        imports.append({
            'import_name': match.group(1),
            'prefix': match.group(2)
        })
    result['imports'] = imports
    
    # Get augments
    augments = []
    augment_matches = re.finditer(r'augment\s+"([^"]+)"', content)
    for match in augment_matches:
        augments.append({
            'augment_path': match.group(1)
        })
    result['augments'] = augments
    
    return result

def process_yang_files(directory: str) -> Dict[str, Dict]:
    yang_files = {}
    
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.yang'):
                file_path = os.path.join(root, file)
                yang_files[file] = parse_yang_file(file_path)
    
    return yang_files

def main():
    # Replace with your yang files directory
    yang_directory = "/home/romandodin/projects/nokia/srlinux-yang-models/srlinux-yang-models/srl_nokia"
    result = process_yang_files(yang_directory)
    
    # Print the results in the requested format
    for file_name, data in result.items():
        print(f"\n{data.get('module_name', 'Unknown module')}:")
        print(f"  prefix: {data.get('prefix', '')}")
        
        if data.get('imports'):
            print("  imports:")
            for imp in data['imports']:
                print(f"    - {imp['import_name']}:")
                print(f"      prefix: {imp['prefix']}")
        
        if data.get('augments'):
            print("  augments:")
            for aug in data['augments']:
                print(f"    augment_path: {aug['augment_path']}")

if __name__ == "__main__":
    main()