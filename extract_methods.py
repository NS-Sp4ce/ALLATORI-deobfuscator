#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import re
from collections import defaultdict
from typing import Dict, List, Tuple

try:
    import javalang
except ImportError:
    print("Error: javalang library is not installed.")
    print("Please run in the command line: pip install javalang")
    exit(1)


def process_list_file(list_file_path: str) -> Dict[str, List[Tuple[str, str, str, List[str]]]]:
    folder_methods = defaultdict(list)
    
    try:
        with open(list_file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        for line in lines:
            line = line.strip()
            if not line or '#' not in line:
                continue

            path_part, signature = line.split('#', 1)
            
            match = re.match(r'([^.]+)\.([^(]+)\(([^)]*)\)', signature)
            if match:
                class_name, method_name, params_str = match.groups()
                param_types = [p.strip() for p in params_str.split(',') if p.strip()]
                
                folder_name = path_part.split('\\')[0]
                folder_methods[folder_name].append((path_part, class_name, method_name, param_types))
            
        return folder_methods

    except FileNotFoundError:
        print(f"Error: Input file {list_file_path} not found.")
        return {}
    except Exception as e:
        print(f"Error reading list.txt file: {str(e)}")
        return {}


def get_param_type_name(param_type_node) -> str:
    if isinstance(param_type_node, javalang.tree.ReferenceType):
        name = param_type_node.name
        dims = '[]' * len(param_type_node.dimensions)
        return f"{name}{dims}"
    elif isinstance(param_type_node, javalang.tree.BasicType):
        name = param_type_node.name
        dims = '[]' * len(param_type_node.dimensions)
        return f"{name}{dims}"
    return 'unknown'

def extract_method_with_regex(content: str, method_name: str, param_types: List[str]) -> str:
    param_patterns = [rf'{re.escape(ptype)}\s+\w+' for ptype in param_types]
    params_regex_str = r'\s*,\s*'.join(param_patterns)
    
    pattern_str = rf"(?:public\s+static\s+String\s+)?{re.escape(method_name)}\s*\(\s*{params_regex_str}\s*\)\s*{{?"
    
    match = re.search(pattern_str, content)
    
    if not match:
        param_str = ','.join(param_types)
        return f"// Regex fallback failed: Could not find method signature {method_name}({param_str})"

    search_start_pos = match.start()
    
    code_block = content[search_start_pos:]
    try:
        first_brace_index = code_block.index('{')
    except ValueError:
        return f"// Regex fallback failed: Could not find starting '{{' for method {method_name}"
        
    brace_count = 1
    end_index = -1
    
    for i, char in enumerate(code_block[first_brace_index + 1:]):
        if char == '{':
            brace_count += 1
        elif char == '}':
            brace_count -= 1
        
        if brace_count == 0:
            end_index = first_brace_index + 1 + i
            break
            
    if end_index != -1:
        return code_block[:end_index + 1]
    else:
        return f"// Regex fallback failed: Mismatched braces for method {method_name}"

def extract_method_from_file(file_path: str, class_name: str, method_name: str, param_types: List[str]) -> str:
    try:
        if not os.path.exists(file_path):
            return f"// File does not exist: {file_path}"

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        tree = javalang.parse.parse(content)
        target_node = None

        is_constructor_search = (method_name == class_name)
        node_type_to_search = javalang.tree.ConstructorDeclaration if is_constructor_search else javalang.tree.MethodDeclaration
        
        for path, node in tree.filter(node_type_to_search):
            if node.name == method_name:
                parent_class = next((p for p in reversed(path) if isinstance(p, (javalang.tree.ClassDeclaration, javalang.tree.EnumDeclaration))), None)
                if parent_class and parent_class.name == class_name:
                    node_param_types = [get_param_type_name(p.type) for p in node.parameters]
                    if node_param_types == param_types:
                        target_node = node
                        break
        
        if not target_node or not target_node.position:
            param_str = ','.join(param_types)
            return f"// javalang: No matching declaration found in file {file_path}: {class_name}.{method_name}({param_str})"

        lines = content.splitlines()
        start_line = target_node.position.line
        if hasattr(target_node, 'annotations') and target_node.annotations:
            start_line = min(ann.position.line for ann in target_node.annotations)
        
        code_block = '\n'.join(lines[start_line - 1:])
        
        try:
            first_brace_index = code_block.index('{')
        except ValueError:
            return f"// javalang: Could not find starting '{{' for {method_name}"

        brace_count = 1
        end_index = -1
        
        for i, char in enumerate(code_block[first_brace_index + 1:]):
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
            
            if brace_count == 0:
                end_index = first_brace_index + 1 + i
                break
        
        if end_index != -1:
            return code_block[:end_index + 1]
        else:
            return f"// javalang: Mismatched braces for {method_name}"

    except (javalang.tokenizer.LexerError, javalang.parser.JavaSyntaxError) as e:
        return extract_method_with_regex(content, method_name, param_types)
        
    except Exception as e:
        return f"// Unexpected error while processing file {file_path}: {str(e)}"


def extract_all_methods():
    list_file_path = "list.txt"
    folder_to_methods_map = process_list_file(list_file_path)

    if not folder_to_methods_map:
        print("No valid method information found in list.txt, or the format is incorrect. Please ensure the format is '...#ClassName.methodName(param1,param2)'")
        return

    print("Starting to extract method definitions...")
    
    for folder_name, methods in folder_to_methods_map.items():
        simple_folder_name = folder_name.split('\\')[0]
        output_file = f"method_{simple_folder_name}_all_extracted.txt"
        
        print(f"\nProcessing folder: {folder_name}")
        print(f"Output file will be: {output_file}")
        print(f"Found {len(methods)} methods to extract.")

        sorted_methods = sorted(methods)

        with open(output_file, 'w', encoding='utf-8') as f:
            for path_part, class_name, method_name, param_types in sorted_methods:
                param_str = ','.join(param_types)
                header = f"{path_part}#{class_name}.{method_name}({param_str})"
                print(f"  -> Processing: {header}")
                
                file_path = path_part.replace('\\', os.sep)
                method_code = extract_method_from_file(file_path, class_name, method_name, param_types)
                
                f.write("========METHOD===NAME===START=======\n")
                f.write(f"{header}\n")
                f.write("========METHOD===NAME===END=======\n")
                f.write("========METHOD===CODE===START=======\n")
                f.write(method_code + "\n")
                f.write("========METHOD===CODE===END=======\n\n")
        
        print(f"Successfully created and wrote to file: {output_file}")
    
    print("\nAll operations completed!")


if __name__ == "__main__":
    extract_all_methods()

