import os
import re
import argparse
import pandas as pd

TAG_IMPORTS = [
    "import edu.neu.ccs.prl.galette.internal.runtime.Tag;",
    "import edu.neu.ccs.prl.galette.internal.runtime.Tainter;"
]

SOURCE_DIR = "./BenchmarkJava"
QL_RESULTS_DIR = "SAST_Module/ql_results"

def find_csv_for_cwe(cwe):
    if cwe.strip().lower() == "demo":
        cwe_dir = os.path.join(QL_RESULTS_DIR, "cwe-demo")
    else:
        cwe_id = cwe.strip().zfill(3)
        cwe_dir = os.path.join(QL_RESULTS_DIR, f"cwe-{cwe_id}")
    if not os.path.exists(cwe_dir):
        print(f"[!] CWE folder not found: {cwe_dir}")
        return None
    for file in os.listdir(cwe_dir):
        if file.endswith(".csv"):
            return os.path.join(cwe_dir, file)
    return None

def build_class_file_map(base_dir):
    mapping = {}
    for root, _, files in os.walk(base_dir):
        for f in files:
            if f.endswith(".java"):
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, base_dir).replace("/", ".").replace("\\", ".")
                class_name = rel_path[:-5]
                mapping[class_name] = full_path
    return mapping

def insert_imports(lines):
    content = "".join(lines)
    for tag_import in TAG_IMPORTS:
        if tag_import not in content:
            for i, line in enumerate(lines):
                if line.strip().startswith("package "):
                    lines.insert(i + 1, tag_import + "\n")
                    break
    return lines

def insert_code(lines, line_number, snippet):
    snippet_lines = ["    " + l + "\n" for l in snippet]
    lines[line_number:line_number] = snippet_lines
    return lines

def process_file(file_path, injections):
    if not os.path.exists(file_path):
        print(f"[!] File not found: {file_path}")
        return
    with open(file_path, "r") as f:
        lines = f.readlines()
    lines = insert_imports(lines)
    injections_sorted = sorted(injections, key=lambda x: x["line"], reverse=True)
    for inj in injections_sorted:
        lines = insert_code(lines, inj["line"], inj["snippet"])
    with open(file_path, "w") as f:
        f.writelines(lines)
    print(f"[!] Instrumented {file_path}")

def main():
    parser = argparse.ArgumentParser(description="Galette Instrument Script")
    parser.add_argument("--cwe", required=True, help="CWE type (22, 78, 89, or demo)")
    args = parser.parse_args()

    csv_path = find_csv_for_cwe(args.cwe)
    if not csv_path:
        print(f"[!] Not found CSV for CWE-{args.cwe}")
        return

    print(f"[!] Found CSV: {csv_path}")
    df = pd.read_csv(csv_path)

    print(f"[!] Scanning Java source directory: {SOURCE_DIR}")
    class_map = build_class_file_map(SOURCE_DIR)

    file_injections = {}

    for _, row in df.iterrows():
        src_class = row["col0"]
        sink_class = row["col4"]
        src_line = int(row["col3"])
        sink_line = int(row["col7"])

        source_var = row["col2"].split("(")[0].strip()
        sink_var = row["col6"].strip()

        source_snippet = [
            'Tag tag = Tag.of("source: Tainted");',
            f'{source_var} = Tainter.setTag({source_var}, tag);',
            'System.out.println("✅ [GAL] Taint set at source! Tag = " + tag);'
        ]

        sink_snippet = [
            f'Tag tagCheck = Tainter.getTag({sink_var});',
            'System.out.println("📌 [GAL] Sink reached. Tag = " + tagCheck);',
            'if (tagCheck != null) {',
            '    System.out.println("🔥 [GAL] Taint reached sink! Confirmed propagation.");',
            '} else {',
            '    System.out.println("❌ [GAL] No taint detected at sink.");',
            '}'
        ]

        if src_class in class_map:
            file_injections.setdefault(class_map[src_class], []).append({"line": src_line, "snippet": source_snippet})
        else:
            print(f"[!] Source class not found: {src_class}")

        if sink_class in class_map:
            file_injections.setdefault(class_map[sink_class], []).append({"line": sink_line, "snippet": sink_snippet})
        else:
            print(f"[!] Sink class not found: {sink_class}")

    for file_path, injections in file_injections.items():
        process_file(file_path, injections)

if __name__ == "__main__":
    main()
