import re
import sys

def java_eval(expr):
    try:
        fixed_expr = re.sub(r'((?:\d+|\([^)]+\))\s*<<\s*\d+)', r'(\1)', expr)
        return eval(fixed_expr)
    except Exception:
        return f"(Cannot evaluate: {expr})"

def trace_key_values(body_lines):
    var_states = {}
    
    pre_loop_lines = []
    loop_line_and_body = []
    found_loop = False

    for line in body_lines:
        if line.strip().startswith('for'):
            found_loop = True
        if not found_loop:
            pre_loop_lines.append(line)
        else:
            loop_line_and_body.append(line)

    assignment_regex = re.compile(r'^\s*(?:(?:int|byte)\s+)?(var\d+)\s*=\s*(.*?);')
    
    for line in pre_loop_lines:
        match = assignment_regex.match(line.strip())
        if match:
            dest_var, value_part = match.groups()
            if value_part in var_states:
                var_states[dest_var] = var_states[value_part]
            else:
                var_states[dest_var] = value_part

    if not loop_line_and_body:
        return []

    final_keys = []
    
    loop_init_regex = re.search(r'for\s*\(\s*(?:int|byte)\s+var\d+\s*=\s*(.*?);', loop_line_and_body[0])
    if loop_init_regex:
        key1_source = loop_init_regex.group(1).strip()
        final_keys.append(var_states.get(key1_source, key1_source))

    if 'var4' in var_states:
        final_keys.append(var_states['var4'])
        
    return final_keys

def parse_entries_from_content(content):
    entries = []
    log_entries = []

    pattern = re.compile(
        r"========METHOD===NAME===START=======\s*(.*?)\s*========METHOD===NAME===END=======\s*"
        r"========METHOD===CODE===START=======\s*(.*?)\s*========METHOD===CODE===END=======",
        re.DOTALL
    )

    matches = pattern.findall(content)

    for header, body in matches:
        cleaned_header = header.strip()
        cleaned_body = body.strip()
        if cleaned_header and cleaned_body:
            entries.append({'header': cleaned_header, 'body': cleaned_body})
        else:
            log_entries.append(f"Warning: Found an empty header or code block, skipped. Header: {cleaned_header[:100]}...")
    
    return entries, log_entries

def main():
    if len(sys.argv) < 2:
        print("Usage: python extract_keys_fixed.py <filename>")
        print("Example: python extract_keys_fixed.py list.txt")
        return

    file_path = sys.argv[1]
    file_name=file_path.replace('.txt', '').replace('.', '_')
    output_file_path = 're-'+file_name+'.txt'
    log_file_path = 'processing_log-'+file_name+'.txt'

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return

    matches, parsing_logs = parse_entries_from_content(content)
    
    log_entries = parsing_logs
    total_blocks = len(matches)
    processed_count = 0
    
    print(f"Info: Found {total_blocks} valid entries to process in {file_path}. Starting processing...")

    with open(output_file_path, 'w', encoding='utf-8') as out_file:
        out_file.write("# Note: The key values below are dynamically calculated from the file based on Java operator precedence.\n")
        out_file.write("# If the values do not match your expectations, please check the expressions in the source file (list.txt).\n")
        out_file.write("patterns_map = {\n")

        for entry in matches:
            header = entry['header']
            body = entry['body']
            current_log = [f"Processing: {header}"]

            body_lines = body.strip().split('\n')
            keys_exprs = trace_key_values(body_lines)

            if not keys_exprs:
                current_log.append("Status: Failed - Could not identify any Key expressions in this method.")
                log_entries.append("\n".join(current_log))
                continue

            key_values = []
            for i, expr in enumerate(keys_exprs):
                val = java_eval(expr)
                key_values.append(val)
                current_log.append(f"- Key {i+1} Expression: {expr}")
                current_log.append(f"- Key {i+1} Calculated Value: {val}")

            is_successful = all(isinstance(v, int) for v in key_values)
            
            if is_successful:
                current_log.append("Status: Success, written to re.txt")
                processed_count += 1
                
                clean_header = header.split('(')[0]
                map_key = clean_header.split('#')[-1]
                
                key_values_tuple = tuple(key_values)
                re_pattern_key = map_key.replace('.', r'\.')
                regex_pattern_str = f"r'(?<![\\w.]){re_pattern_key}\\(\"((?:\\\\.|[^\"\\\\])*)\"\\)'"
                out_file.write(f"    '{map_key}': (re.compile({regex_pattern_str}), {key_values_tuple}),\n")
            else:
                current_log.append("Status: Failed, not written to re.txt")

            log_entries.append("\n".join(current_log))

        out_file.write("}\n")

    with open(log_file_path, 'w', encoding='utf-8') as log_file:
        log_file.write(f"Processing Log: Found {total_blocks} valid entries, successfully processed {processed_count}.\n\n")
        log_file.write("\n----------------------------------------\n".join(log_entries))
        log_file.write("\n")
    
    print(f"Processing complete. Successfully wrote {processed_count} entries to '{output_file_path}'")
    print(f"Detailed processing log has been written to '{log_file_path}'")


if __name__ == '__main__':
    main()

