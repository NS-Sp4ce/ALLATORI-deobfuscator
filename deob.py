import os
import re
import glob
import sys
from typing import Tuple, List, Dict

def unescape_java_string(s: str) -> str:
    _ESCAPE_MAP = {
        't': '\t', 'b': '\b', 'n': '\n', 'f': '\f', 'r': '\r',
        '"': '"', "'": "'", '\\': '\\'
    }

    def replace_match(match: re.Match) -> str:
        esc = match.group(1)
        if esc.startswith('u'):
            try:
                return chr(int(esc[1:], 16))
            except ValueError:
                return match.group(0)
        if esc[0] in '01234567':
            try:
                return chr(int(esc, 8))
            except ValueError:
                return match.group(0)
        if esc in _ESCAPE_MAP:
            return _ESCAPE_MAP[esc]
        return match.group(0)

    escape_pattern = re.compile(r'\\(u[0-9a-fA-F]{4}|[0-7]{1,3}|[btnfr"\'\\])')
    return escape_pattern.sub(replace_match, s)


def deobfuscate_method_logic(obfuscated: str, key_a: int, key_b: int) -> str:
    if not obfuscated:
        return ""

    s_chars = list(obfuscated)
    result_chars = [''] * len(s_chars)
    index = len(s_chars) - 1

    while index >= 0:
        result_chars[index] = chr(ord(s_chars[index]) ^ key_a)
        index -= 1
        if index < 0:
            break
        result_chars[index] = chr(ord(s_chars[index]) ^ key_b)
        index -= 1

    return "".join(result_chars)

def escape_for_java_string_literal(s: str) -> str:
    escaped_string = ""
    for char in s:
        if char == '"':
            escaped_string += '\\"'
        elif char == '\\':
            escaped_string += '\\\\'
        elif char == '\n':
            escaped_string += '\\n'
        elif char == '\r':
            escaped_string += '\\r'
        elif char == '\t':
            escaped_string += '\\t'
        elif char == '\b':
            escaped_string += '\\b'
        elif char == '\f':
            escaped_string += '\\f'
        elif ord(char) < 32:
            escaped_string += f'\\u{ord(char):04x}'
        else:
            escaped_string += char
    return escaped_string


def get_patterns_map() -> Dict[str, Tuple[re.Pattern, Tuple[int, int]]]:
    #############
    #CHANGE HERE#
    #############
    patterns_map = {}
    #############
    #CHANGE HERE#
    #############
    return patterns_map

def find_matching_brace(text: str, start_index: int) -> int:
    if text[start_index] != '{':
        return -1

    brace_count = 1
    in_string = False

    for i in range(start_index + 1, len(text)):
        char = text[i]

        if char == '"':
            is_escaped = False
            p = i - 1
            while p >= 0 and text[p] == '\\':
                is_escaped = not is_escaped
                p -= 1

            if not is_escaped:
                in_string = not in_string

        if not in_string:
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1

        if brace_count == 0:
            return i

    return -1

def split_code_into_scoped_chunks(file_content: str) -> List[Dict[str, str]]:
    chunks = []
    last_end = 0
    search_pos = 0
    current_line_number = 1

    method_pattern = re.compile(
        r'((?:@[\w\d]+\s*\n?\s*)*'
        r'(?:public|private|protected|static|final|synchronized|abstract|\s)*'
        r'[\w\d\.<>\[\],?\s]+\s+'
        r'([\w\d_$]+)\s*'
        r'\(.*?\)\s*'
        r'(?:throws\s+[\w\d\.,\s]+)?\s*)'
        r'(\{)', re.MULTILINE | re.DOTALL
    )

    while search_pos < len(file_content):
        match = method_pattern.search(file_content, pos=search_pos)
        if not match:
            break

        method_header_start = match.start(1)
        brace_start = match.start(3)

        if method_header_start > last_end:
            content_before = file_content[last_end:method_header_start]
            chunks.append({
                'type': 'global',
                'content': content_before,
                'start_line': current_line_number
            })
            current_line_number += content_before.count('\n')

        brace_end = find_matching_brace(file_content, brace_start)
        if brace_end != -1:
            method_full_text = file_content[method_header_start:brace_end + 1]
            chunks.append({
                'type': 'method',
                'content': method_full_text,
                'start_line': current_line_number
            })
            current_line_number += method_full_text.count('\n')
            last_end = brace_end + 1
            search_pos = last_end
        else:
            last_end = method_header_start
            search_pos = match.end()

    if last_end < len(file_content):
        content_after = file_content[last_end:]
        chunks.append({
            'type': 'global',
            'content': content_after,
            'start_line': current_line_number
        })

    return chunks

def resolve_line_recursively(line_to_search: str, file_content: str, patterns_map: dict, internal_patterns_cache: dict, current_class: str) -> str:
    modified_line = line_to_search
    while True:
        all_matches_in_line: List[Tuple[str, re.Match, Tuple[int, int]]] = []

        for class_method, (external_pattern, keys) in patterns_map.items():
            for match_obj in external_pattern.finditer(modified_line):
                all_matches_in_line.append((class_method, match_obj, keys))

        if current_class != "UnknownClass" and current_class in internal_patterns_cache:
            for method_name, (internal_pattern, keys) in internal_patterns_cache[current_class].items():
                for match_obj in internal_pattern.finditer(modified_line):
                    log_key = f'{current_class}.{method_name} (Internal)'
                    all_matches_in_line.append((log_key, match_obj, keys))

        if not all_matches_in_line:
            break

        all_matches_in_line.sort(key=lambda x: x[1].start(), reverse=True)

        class_method, match_obj, original_keys = all_matches_in_line[0]
        start, end = match_obj.span()
        encrypted_str = match_obj.group(1)

        try:
            final_keys = original_keys

            processed_str = unescape_java_string(encrypted_str)
            decrypted = deobfuscate_method_logic(processed_str, final_keys[0], final_keys[1])
            decrypted_escaped = escape_for_java_string_literal(decrypted)
            
            replacement = f'"{decrypted_escaped}"'
            
            modified_line = modified_line[:start] + replacement + modified_line[end:]
        except Exception:
            return modified_line

    return modified_line

def process_file_content(file_content: str, log_file, patterns_map: dict, internal_patterns_cache: dict, known_call_substrings: List[str], file_class_name: str, start_line_offset: int) -> Tuple[str, bool, List[str]]:
    original_content = file_content
    current_content = file_content
    max_iterations = 10
    iteration = 0

    while iteration < max_iterations:
        iteration += 1
        log_file.write(f"\n<<<<<<<<<< Starting Iteration {iteration} >>>>>>>>>>\n")
        content_before_this_iteration = current_content
        current_class = file_class_name

        log_file.write("\n--- Starting Pass 1: Variable Resolution ---\n")
        resolved_vars = {}
        assignment_lines_to_comment = set()
        assignment_pattern = re.compile(
            r'^(?P<indent>\s*)(?:final\s+)?String\s+(?P<var_name>[\w\d_$]+)\s*=\s*(?P<rhs>.*?);', re.MULTILINE
        )
        current_lines = content_before_this_iteration.splitlines()
        for match in assignment_pattern.finditer(content_before_this_iteration):
            var_name = match.group('var_name')
            rhs = match.group('rhs').strip()
            full_line_text = match.group(0).strip()
            line_start_pos = match.start()
            line_number = content_before_this_iteration.count('\n', 0, line_start_pos)
            if line_number < len(current_lines) and current_lines[line_number].strip().startswith('//'):
                continue
            is_known_call = any(call in rhs for call in known_call_substrings)
            is_plain_string = rhs.startswith('"') and rhs.endswith('"')
            if not (is_known_call or is_plain_string):
                continue
            try:
                resolved_rhs = resolve_line_recursively(rhs, content_before_this_iteration, patterns_map, internal_patterns_cache, current_class)
                string_literal_match = re.fullmatch(r'"((?:\\.|[^"\\])*)"', resolved_rhs)
                if string_literal_match:
                    decrypted_val_escaped = string_literal_match.group(1)
                    decrypted_val_raw = unescape_java_string(decrypted_val_escaped)
                    resolved_vars[var_name] = decrypted_val_raw
                    assignment_lines_to_comment.add(full_line_text)
                    log_file.write(f"[ITER {iteration} | PASS 1] Resolved variable '{var_name}'\n\t- From: {full_line_text}\n\t- To Value (raw): {decrypted_val_raw}\n")
            except Exception as e:
                log_file.write(f"[ITER {iteration} | PASS 1] ERROR resolving variable '{var_name}': {e}\n")
                continue
        if not resolved_vars:
            log_file.write(f"[ITER {iteration} | PASS 1] No new variables resolved in this iteration.\n")

        log_file.write("\n--- Starting Pass 2: Scope-Aware Variable Substitution ---\n")
        lines = content_before_this_iteration.splitlines()
        new_lines_pass2 = []
        
        active_vars_for_substitution = resolved_vars.copy()
        redeclaration_pattern = re.compile(r'^\s*([\w\d\.<>\[\]]+\s+)([\w\d_$]+)\s*[=;\(]')

        for line_num, line in enumerate(lines, 1):
            vars_for_this_line = active_vars_for_substitution.copy()

            stripped_line = line.strip()

            if stripped_line.startswith('//'):
                new_lines_pass2.append(line)
                continue
                
            if stripped_line in assignment_lines_to_comment:
                indent = re.match(r'^\s*', line).group(0)
                commented_line = f"{indent}//{stripped_line}"
                var_name_match = re.search(r'\bString\s+([\w\d_$]+)\s*=', stripped_line)
                if var_name_match:
                    var_name = var_name_match.group(1)
                    if var_name in resolved_vars:
                        decrypted_value = resolved_vars[var_name]
                        escaped_value = escape_for_java_string_literal(decrypted_value)
                        commented_line = f'{indent}//{stripped_line} [DECRYPTED] {var_name} = "{escaped_value}";'
                new_lines_pass2.append(commented_line)
                log_file.write(f"[ITER {iteration} | PASS 2] Line {line_num}: Commented out original assignment: {commented_line.strip()}\n")
                continue
            
            line_code_part = re.sub(r'\s*//.*$', '', line)
            modified_line_code_part = line_code_part

            if vars_for_this_line:
                sorted_vars = sorted(vars_for_this_line.keys(), key=len, reverse=True)
                var_regex_parts = [r'\b' + re.escape(v) + r'\b' for v in sorted_vars]
                combined_pattern = re.compile('|'.join(var_regex_parts))

                declaration_match = redeclaration_pattern.search(line_code_part)
                declaration_pos = -1
                if declaration_match:
                    declaration_pos = declaration_match.start(2)

                def replacer(match):
                    if declaration_pos != -1 and match.start() == declaration_pos:
                        return match.group(0)
                    
                    following_text = line_code_part[match.end():].lstrip()
                    if following_text.startswith('=') and not following_text.startswith('=='):
                        return match.group(0)

                    matched_var = match.group(0)
                    if matched_var in vars_for_this_line:
                        decrypted_val = vars_for_this_line[matched_var]
                        escaped_val = escape_for_java_string_literal(decrypted_val)
                        return f'"{escaped_val}"'
                    return match.group(0)

                modified_line_code_part = combined_pattern.sub(replacer, line_code_part)

            declaration_match_for_scope_update = redeclaration_pattern.search(line_code_part)
            if declaration_match_for_scope_update:
                var_name = declaration_match_for_scope_update.group(2)
                if var_name in active_vars_for_substitution:
                    log_file.write(f"[ITER {iteration} | PASS 2] Line {line_num}: Forgetting '{var_name}' for subsequent lines due to re-declaration: {stripped_line}\n")
                    active_vars_for_substitution.pop(var_name, None)
            
            was_modified = modified_line_code_part != line_code_part
            if was_modified:
                final_line = f"{modified_line_code_part.rstrip()} //{stripped_line}"
                new_lines_pass2.append(final_line)
                log_file.write(f"[ITER {iteration} | PASS 2] Line {line_num}: Substituted variable(s). New line: {final_line.strip()}\n")
            else:
                new_lines_pass2.append(line)

        line_separator = '\r\n' if '\r\n' in content_before_this_iteration else '\r' if '\r' in content_before_this_iteration else '\n'
        content_after_pass2 = line_separator.join(new_lines_pass2)

        log_file.write("\n--- Starting Pass 3: Final Decryption ---\n")
        lines_after_pass2 = content_after_pass2.splitlines()
        final_lines = []
        for line_num, line in enumerate(lines_after_pass2, 1):
            original_line_for_log = line.strip()
            if line.strip().startswith('//'):
                final_lines.append(line)
                continue
            line_to_search = re.sub(r'\s*//.*$', '', line)
            modified_line = resolve_line_recursively(line_to_search, content_before_this_iteration, patterns_map, internal_patterns_cache, current_class)
            trailing_comment_match = re.search(r'(\s*//.*$)', line)
            if trailing_comment_match:
                modified_line += trailing_comment_match.group(1)
            if original_line_for_log != modified_line.strip():
                log_file.write(f"[ITER {iteration} | PASS 3] Line {line_num}: Decrypted remaining calls. New line: {modified_line.strip()}\n")
            final_lines.append(modified_line)
        current_content = line_separator.join(final_lines)

        if current_content == content_before_this_iteration:
            log_file.write(f"\n<<<<<<<<<< No changes in Iteration {iteration}. Stabilized. >>>>>>>>>>\n")
            break
    if iteration >= max_iterations:
        log_file.write(f"\n<<<<<<<<<< Reached max iterations ({max_iterations}). Stopping. >>>>>>>>>>\n")

    final_content = current_content
    was_modified = final_content != original_content
    console_change_log = []
    if was_modified:
        original_lines = original_content.splitlines()
        final_lines = final_content.splitlines()
        max_len = max(len(original_lines), len(final_lines))
        for i in range(max_len):
            line_orig = original_lines[i] if i < len(original_lines) else ""
            line_final = final_lines[i] if i < len(final_lines) else ""
            if line_orig.strip() != line_final.strip():
                console_change_log.append(f"  Line {i + start_line_offset}:")
                console_change_log.append(f"    - Before: {line_orig.strip()}")
                console_change_log.append(f"    - After:  {line_final.strip()}")

    return final_content, was_modified, console_change_log

def main():
    print("=== Universal String Decryption Tool (v7.1 - Final Scope Fix) ===")
    current_dir = os.getcwd()
    print(f"Searching for .java files in directory: {current_dir}\n")

    patterns_map = get_patterns_map()
    internal_patterns_cache = {}
    for key, (pattern, keys) in patterns_map.items():
        parts = key.split('.')
        if len(parts) < 2:
            print(f"[WARNING] Skipping improperly formatted key '{key}', ensure it is in 'ClassName.MethodName' format.")
            continue
        class_name = parts[-2]
        method_name = parts[-1]
        if class_name not in internal_patterns_cache:
            internal_patterns_cache[class_name] = {}
        internal_pattern = re.compile(rf'(?<![a-zA-Z0-9_.$]){method_name}\("((?:\\.|[^"\\])*)"\)')
        internal_patterns_cache[class_name][method_name] = (internal_pattern, keys)

    known_call_substrings = list(patterns_map.keys())
    java_files = glob.glob(os.path.join(current_dir, '**', '*.java'), recursive=True)

    if not java_files:
        print("No .java files found.")
        return

    modified_files_count = 0
    total_count = len(java_files)
    log_filename = "log_string_deobfuscator.txt"
    if os.path.exists(log_filename): os.remove(log_filename)
    print(f"Logs will be written to: {log_filename}\n")

    with open(log_filename, 'a', encoding='utf-8') as log_file:
        for i, file_path in enumerate(java_files):
            log_file.write(f"\n==================================================\n")
            log_file.write(f"Processing file: {os.path.relpath(file_path)}\n")
            log_file.write(f"==================================================\n")
            print(f"[{i+1}/{total_count}] Processing: {os.path.relpath(file_path)}")
            file_content = None
            used_encoding = None
            for enc in ['utf-8', 'gbk', 'gb2312', 'latin-1']:
                try:
                    with open(file_path, 'r', encoding=enc, newline='') as f:
                        file_content = f.read()
                    used_encoding = enc
                    break
                except (UnicodeDecodeError, FileNotFoundError):
                    continue

            if file_content is None:
                print(f"  - ERROR: Could not read the file.")
                log_file.write("ERROR: Could not read the file with any of the attempted encodings.\n")
                continue

            class_match = re.search(r'class\s+([a-zA-Z0-9_]+)', file_content)
            file_class_name = class_match.group(1) if class_match else "UnknownClass"
            log_file.write(f"\nDetected class for file: {file_class_name}\n")
            
            scoped_chunks = split_code_into_scoped_chunks(file_content)
            final_chunks_content = []
            was_any_chunk_modified = False
            all_changes_for_file = []

            log_file.write(f"File split into {len(scoped_chunks)} scoped chunks.\n")

            for chunk_idx, chunk in enumerate(scoped_chunks):
                chunk_content = chunk['content']
                log_file.write(f"\n--- Processing Chunk {chunk_idx + 1} ({chunk['type']}) ---\n")

                processed_chunk, was_modified_in_chunk, chunk_changes = process_file_content(
                    chunk_content, log_file, patterns_map, internal_patterns_cache, known_call_substrings, file_class_name, chunk.get('start_line', 1)
                )
                final_chunks_content.append(processed_chunk)
                if was_modified_in_chunk:
                    was_any_chunk_modified = True
                    if chunk_changes:
                        all_changes_for_file.extend(chunk_changes)

            if was_any_chunk_modified:
                modified_files_count += 1
                print(f"  - File modified. Details below:")
                for change_line in all_changes_for_file:
                    print(change_line)

                final_content = "".join(final_chunks_content)
                backup_path = file_path + '.backup'
                try:
                    if os.path.exists(backup_path): os.remove(backup_path)
                    os.rename(file_path, backup_path)
                    with open(file_path, 'w', encoding=used_encoding, newline='') as f:
                        f.write(final_content)
                except OSError as e:
                    print(f"  - Failed to write file: {e}")
                    log_file.write(f"ERROR: Failed to write output file: {e}\n")
            else:
                print(f"  - No changes detected, skipping.")


    print(f"\nDecryption complete!")
    print(f"Processed {total_count} files, successfully modified {modified_files_count} files.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation interrupted by user.")
        sys.exit(1)

