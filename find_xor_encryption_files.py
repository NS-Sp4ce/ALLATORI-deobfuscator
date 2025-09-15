#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import re
import sys
import glob
from collections import defaultdict

class Logger(object):
    def __init__(self, filename="analysis_log.txt"):
        self.terminal = sys.stdout
        self.log = open(filename, "w", encoding='utf-8')

    def write(self, message):
        self.terminal.write(message)
        if not message.startswith('\r'):
            self.log.write(message)

    def flush(self):
        self.terminal.flush()
        self.log.flush()

    def close(self):
        self.log.close()

def find_xor_encryption_files(directory):
    xor_files = []
    java_files = glob.glob(os.path.join(directory, "**/*.java"), recursive=True)
    total_files = len(java_files)
    
    for i, java_file in enumerate(java_files):
        progress_message = f"\r  -> Scanning ({i+1}/{total_files}): {os.path.basename(java_file)}{' ' * 20}"
        print(progress_message, end="")
        try:
            with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                if has_xor_encryption_pattern(content):
                    xor_files.append(java_file)
        except Exception as e:
            print("\r" + " " * len(progress_message) + "\r", end="")
            print(f"Error reading file {java_file}: {e}")

    print("\r" + " " * 100 + "\r", end="")
    return xor_files

def has_xor_encryption_pattern(content):
    if re.search(r'\^|<<|>>', content):
        return True
    return False

def find_decryption_methods(content):
    methods = []
    pattern = re.compile(
        r'(?:public|private|protected)\s+static\s+String\s+(\w+)\s*\(([^)]*)\)\s*\{'
    )
    for match in pattern.finditer(content):
        start_brace_pos = match.end() - 1
        brace_count = 1
        end_brace_pos = -1
        for i, char in enumerate(content[start_brace_pos + 1:]):
            if char == '{': brace_count += 1
            elif char == '}': brace_count -= 1
            if brace_count == 0:
                end_brace_pos = start_brace_pos + 1 + i
                break
        
        if end_brace_pos != -1:
            method_body = content[start_brace_pos + 1 : end_brace_pos]
            if '^' in method_body or '<<' in method_body or '>>' in method_body:
                method_name = match.group(1)
                params_str = match.group(2)
                
                param_types = []
                if params_str.strip():
                    params_list = params_str.split(',')
                    for p in params_list:
                        parts = p.strip().split()
                        if len(parts) >= 2:
                            param_type = parts[0]
                            if param_type == 'final':
                                param_type = parts[1]
                            param_types.append(param_type)
                        elif len(parts) == 1 and parts[0]:
                            param_types.append(parts[0])

                methods.append({
                    'name': method_name,
                    'params': param_types,
                    'implementation': method_body.strip()
                })
    return methods

def analyze_xor_encryption_methods(files_to_analyze):
    encryption_methods = {}
    total_files = len(files_to_analyze)
    
    for i, java_file in enumerate(files_to_analyze):
        progress_message = f"\r  -> Analyzing ({i+1}/{total_files}): {os.path.basename(java_file)}{' ' * 20}"
        print(progress_message, end="")
        try:
            with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            methods = find_decryption_methods(content)

            if methods:
                simple_class_name = os.path.basename(java_file).replace('.java', '')
                
                package_match = re.search(r'^\s*package\s+([^;]+);', content, re.MULTILINE)
                package_name = package_match.group(1).strip() if package_match else 'default_package'
                
                fully_qualified_name = f"{package_name}.{simple_class_name}"
                
                encryption_methods[fully_qualified_name] = {'file': java_file, 'methods': methods}
        except Exception as e:
            print("\r" + " " * len(progress_message) + "\r", end="")
            print(f"Error analyzing file {java_file}: {e}")
    
    print("\r" + " " * 100 + "\r", end="")
    return encryption_methods


def extract_xor_parameters(method_content):
    params = {}
    xor_patterns = [
        r'var[0-9]+ = ([0-9]+) << ([0-9]+) \^ ([0-9]+)',
        r'var[0-9]+ = \(([0-9]+) \^ ([0-9]+)\) << ([0-9]+) \^ ([0-9]+)',
        r'int (?:[a-zA-Z_][a-zA-Z0-9_]*) = ([0-9]+) << ([0-9]+) \^ ([0-9]+)',
        r'([0-9]+) << ([0-9]+) \^ ([0-9]+)',
    ]
    
    for pattern in xor_patterns:
        matches = re.findall(pattern, method_content)
        for match in matches:
            try:
                if len(match) == 4 and all(m.isdigit() for m in match[1:]):
                        params[f'xor_key_{len(params)}'] = {'base': int(match[1]), 'shift': int(match[2]), 'xor': int(match[3]), 'calculated': (int(match[1]) << int(match[2])) ^ int(match[3])}
                elif len(match) == 3 and all(m.isdigit() for m in match):
                    params[f'xor_key_{len(params)}'] = {'base': int(match[0]), 'shift': int(match[1]), 'xor': int(match[2]), 'calculated': (int(match[0]) << int(match[1])) ^ int(match[2])}
            except (ValueError, TypeError): continue
    return params

def find_encrypted_strings(files_to_analyze):
    encrypted_usage = defaultdict(list)
    total_files = len(files_to_analyze)

    for i, java_file in enumerate(files_to_analyze):
        progress_message = f"\r  -> Searching ({i+1}/{total_files}): {os.path.basename(java_file)}{' ' * 20}"
        print(progress_message, end="")
        try:
            with open(java_file, 'r', encoding='utf-8', errors='ignore') as f: content = f.read()
            patterns = [
                (r'(\w+)\.([a-zA-Z])\("([^"]+)"\)', 'single_letter_method_call'),
                (r'(\w+)\.decrypt\("([^"]+)"\)', 'decrypt_method_call'),
                (r'"([^"]*\\u[0-9a-fA-F]{4}[^"]*)"', 'unicode_escape'),
            ]
            for pattern, desc in patterns:
                for match in re.findall(pattern, content):
                    if desc == 'single_letter_method_call':
                        class_name, method_name, encrypted_str = match
                        encrypted_usage[f"{class_name}.{method_name}_method_call"].append({'file': java_file, 'encrypted': encrypted_str})
                    elif desc == 'decrypt_method_call':
                        class_name, encrypted_str = match
                        encrypted_usage[f"{class_name}.{desc}"].append({'file': java_file, 'encrypted': encrypted_str})
                    else:
                        encrypted_usage[f"{desc}"].append({'file': java_file, 'encrypted': match})
        except Exception as e:
            print(f"\r{' ' * len(progress_message)}\rError reading file {java_file}: {e}")
    print(f"\r{' ' * 100}\r", end="")
    return encrypted_usage

def write_summary_files(directory, xor_files, encryption_methods):
    print("\nWriting summary files...")

    with open("files_to_decrypt.txt", "w", encoding="utf-8") as f:
        f.write("======Files to Decrypt======\n")
        for file_path in sorted(xor_files):
            f.write(f"{os.path.relpath(file_path, directory)}\n")

    with open("decryption_classes.txt", "w", encoding="utf-8") as f:
        f.write("======Classes with Encryption Methods======\n")
        class_files = sorted(list(set(info['file'] for info in encryption_methods.values())))
        for file_path in class_files:
            f.write(f"{os.path.relpath(file_path, directory)}\n")

    with open("decryption_methods.txt", "w", encoding="utf-8") as f:
        f.write("======Encryption Methods List (for extraction script)======\n")
        for fq_class_name, info in sorted(encryption_methods.items()):
            relative_path = os.path.relpath(info['file'], directory)
            
            simple_class_name = fq_class_name.split('.')[-1]

            for method in info['methods']:
                method_name = method['name']
                params = method.get('params', [])
                params_str = ','.join(params)
                f.write(f"{relative_path}#{simple_class_name}.{method_name}({params_str})\n")
    
    print("Summary files written successfully.")

def main():
    original_stdout = sys.stdout
    logger = Logger("analysis_log.txt")
    sys.stdout = logger
    directory = "."
    xor_files, encryption_methods = [], {}

    try:
        print("=" * 80 + "\nXOR Encryption/Decryption File Finder (Regex Scan Version)\n" + "=" * 80)
        
        print("\n1. [Quick Scan] Finding Java files potentially containing XOR encryption...")
        xor_files = find_xor_encryption_files(directory)
        
        if not xor_files:
            print("No Java files with XOR/bitwise shift features were found.")
            return
        print(f"Scan complete. Found {len(xor_files)} candidate files.")
        
        print(f"\n2. [Regex Analysis] Analyzing encryption methods in {len(xor_files)} files...")
        encryption_methods = analyze_xor_encryption_methods(xor_files)
        
        print(f"Analysis complete. Identified encryption methods in {len(encryption_methods)} classes:")
        for fq_class_name, info in encryption_methods.items():
            relative_path = os.path.relpath(info['file'], directory)
            print(f"\n  - {fq_class_name}: {relative_path}")
            print(f"    Number of methods: {len(info['methods'])}")
            for method in info['methods']:
                params = method.get('params', [])
                params_str = ','.join(params)
                print(f"    Method {method['name']}({params_str}):")
                params = extract_xor_parameters(method['implementation'])
                if params:
                    print(f"      XOR parameters:")
                    for param_name, param_info in params.items():
                        print(f"        {param_name}: {param_info}")
        
        print(f"\n3. [String Analysis] Searching for encrypted string usage in {len(xor_files)} files...")
        encrypted_usage = find_encrypted_strings(xor_files)
        
        print("Search complete.")
        for usage_type, usages in encrypted_usage.items():
            print(f"\n  {usage_type}: {len(usages)} uses")
            for i, usage in enumerate(usages):
                if i >= 5:
                    print(f"    ... and {len(usages) - 5} more")
                    break
                relative_path = os.path.relpath(usage['file'], directory)
                print(f"    - {relative_path}: {repr(usage['encrypted'])}")
        
    finally:
        print("\n" + "=" * 80 + "\nAnalysis Complete\n" + "=" * 80)
        if isinstance(sys.stdout, Logger):
            sys.stdout.close()
        sys.stdout = original_stdout

    if xor_files:
        write_summary_files(directory, xor_files, encryption_methods)


if __name__ == "__main__":
    main()
