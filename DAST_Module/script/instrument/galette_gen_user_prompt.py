import os
import sys
import re
import argparse
import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))
from directory import (
    PROJECT_SOURCE_CODE_JAVA_DIR,
    CODEQL_REUSLT,
    GALETTE_INSTRUMENT_RESULTS
)
from DAST_Module.src.prompt_instrument import (
    PROMPT_USER_TAGGING_SOURCE,
    PROMPT_USER_TAGGING_SINK,
    PROMPT_USER_TAGGING_COMBINED,
    FEW_SHOT_EXAMPLES,
    CWE_INFO,
)

def read_input_file(filepath):
    if filepath.endswith(".csv"):
        df = pd.read_csv(filepath)
    elif filepath.endswith(".xlsx"):
        df = pd.read_excel(filepath)
    else:
        raise ValueError(f"! File not found: {filepath}")
    return df, os.path.basename(filepath)

def class_name_to_path(full_class_name: str) -> str:
    file_name = full_class_name.split('.')[-1] + ".java"
    for root, _, files in os.walk(PROJECT_SOURCE_CODE_JAVA_DIR):
        if file_name in files:
            return os.path.join(root, file_name)
    return None

def extract_java_method(code: str, method_name: str) -> str:
    pattern = rf"(?:@[^\n]+\n)?(public|protected|private)[\s\S]+?{method_name}\s*\(.*?\)\s*(?:throws [\w.,\s]+)?\{{[\s\S]*?\n\}}"
    match = re.search(pattern, code)
    return match.group(0) if match else None

def extract_code_snippet_near_line(code: str, line_number: int, context: int = 10) -> str:
    lines = code.splitlines()
    start = max(0, line_number - context - 1)
    end = min(len(lines), line_number + context)
    snippet = "\n".join(lines[start:end])
    if not snippet.strip():
        return "// [No snippet found]"
    return "// [Method not found by regex — showing snippet]\n" + snippet

def extract_package_and_imports(code: str) -> str:
    lines = code.splitlines()
    package_line = ""
    import_lines = []

    for line in lines:
        striped = line.strip()
        if striped.startswith("package "):
            package_line = striped
        elif striped.startswith("import "):
            import_lines.append(striped)

    result = []
    if package_line:
        result.append(package_line)
    if import_lines:
        result.extend(import_lines)

    if not result:
        return "// [No package/import found]"
    return "\n".join(result)

def generate_user_tagging_prompts(cwe_id: str):
    is_demo = cwe_id.strip().lower() == "demo"
    actual_cwe_id = "022" if is_demo else cwe_id.strip().zfill(3)
    cwe_info = CWE_INFO.get(actual_cwe_id, "Unknown CWE")

    input_dir = os.path.join(CODEQL_REUSLT, "cwe-demo" if is_demo else f"cwe-{actual_cwe_id}")
    output_dir = os.path.join(GALETTE_INSTRUMENT_RESULTS, "user_prompt_rs", "cwe-demo" if is_demo else f"cwe-{actual_cwe_id}")

    if not os.path.isdir(input_dir):
        print(f"[!] Can't not find input directory: {input_dir}")
        return

    os.makedirs(output_dir, exist_ok=True)
    total = 0

    for file in os.listdir(input_dir):
        input_path = os.path.join(input_dir, file)
        if not (input_path.endswith(".csv") or input_path.endswith(".xlsx")):
            continue
        try:
            df, filename = read_input_file(input_path)
        except Exception as e:
            print(f"[!] Can' read {input_path}: {e}")
            continue

        print(f"Processing: {filename} ({len(df)} lines)")

        for idx, row in df.iterrows():
            try:
                source_class = row["col0"]
                source_method = row["col1"]
                source_expr = row["col2"]
                source_line = row["col3"]
                sink_class = row["col4"]
                sink_method = row["col5"]
                sink_expr = row["col6"]
                sink_line = row["col7"]
            except KeyError:
                continue

            source_path = class_name_to_path(source_class)
            sink_path = class_name_to_path(sink_class)

            if (source_path is None or not os.path.exists(source_path)) and (
                sink_path is None or not os.path.exists(sink_path)):
                print(f"[!] Can't find file java for line {idx}: {source_class}, {sink_class}")
                continue

            java_code_source = ""
            package_import_source = "// [No package/import found]"
            if source_path and os.path.exists(source_path):
                with open(source_path, "r", encoding="utf-8") as f:
                    java_code_source = f.read()
                    package_import_source = extract_package_and_imports(java_code_source)

            java_code_sink = ""
            package_import_sink = "// [No package/import found]"
            if sink_path and os.path.exists(sink_path):
                with open(sink_path, "r", encoding="utf-8") as f:
                    java_code_sink = f.read()
                    package_import_sink = extract_package_and_imports(java_code_sink)

            source_method_code = extract_java_method(java_code_source, source_method)
            if not source_method_code:
                try:
                    line_num = int(source_line) if not pd.isna(source_line) else 1
                except:
                    line_num = 1
                source_method_code = extract_code_snippet_near_line(java_code_source, line_num)
            source_method_code = str(source_method_code)

            sink_method_code = extract_java_method(java_code_sink, sink_method)
            if not sink_method_code:
                try:
                    line_num = int(sink_line) if not pd.isna(sink_line) else 1
                except:
                    line_num = 1
                sink_method_code = extract_code_snippet_near_line(java_code_sink, line_num)
            sink_method_code = str(sink_method_code)

            file_name_source = os.path.basename(source_path) if source_path else "UnknownSource.java"
            file_name_sink = os.path.basename(sink_path) if sink_path else "UnknownSink.java"

            prompt_source = PROMPT_USER_TAGGING_SOURCE.format(
                source_class=source_class,
                source_method=source_method,
                source=source_expr,
                source_line=source_line,
                file_name=file_name_source,
                java_method=source_method_code,
                package_import=package_import_source
            )

            prompt_sink = PROMPT_USER_TAGGING_SINK.format(
                sink_class=sink_class,
                sink_method=sink_method,
                sink=sink_expr,
                sink_line=sink_line,
                file_name=file_name_sink,
                java_method=sink_method_code,
                cwe_info=cwe_info,
                package_import=package_import_sink
            )

            prompt_combined = PROMPT_USER_TAGGING_COMBINED.format(
                user_tagging_source=prompt_source,
                user_tagging_sink=prompt_sink,
            )

            out_path = os.path.join(output_dir, file_name_source.replace(".java", f"_user_prompt_{idx}.txt"))
            with open(out_path, "w", encoding="utf-8") as out:
                out.write(prompt_combined)
            total += 1

    print(f"[!] Total {total} prompt(s) written in: {output_dir}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Prompt tagging from CodeQL Result")
    parser.add_argument("--cwe", required=True, help="CWE ID (ex: 022, 078, 089, or 'demo')")
    args = parser.parse_args()
    generate_user_tagging_prompts(args.cwe)
