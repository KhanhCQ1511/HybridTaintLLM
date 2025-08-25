import os
import sys
import json
import ast
import pandas as pd
import argparse

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
import directory
from LLM.src.prompt import PROMPT_USER, CWE_HINTS

def find_input_file(input_dir):
    for file in os.listdir(input_dir):
        if file.endswith(".csv") or file.endswith(".xlsx"):
            return os.path.join(input_dir, file)
    return None

def read_input_file(filepath):
    if filepath.endswith(".csv"):
        return pd.read_csv(filepath)
    elif filepath.endswith(".xlsx"):
        return pd.read_excel(filepath)
    else:
        raise ValueError("[!] File not valid")

def extract_code_snippet(full_class_name, line_number, context=5, marker="// ← HERE"):
    relative_path = full_class_name.replace("org.owasp.benchmark.", "").replace(".", "/") + ".java"
    abs_path = os.path.join(directory.PROJECT_SOURCE_CODE_JAVA_DIR_BU, relative_path)

    if not os.path.exists(abs_path):
        return f"// [Source file not found: {relative_path}]"

    try:
        with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        idx = max(0, int(line_number) - 1)
        start = max(0, idx - context)
        end = min(len(lines), idx + context + 1)

        snippet = ""
        for i in range(start, end):
            line = lines[i].rstrip()
            if i == idx:
                line += f"   {marker}"
            snippet += f"    {line}\n"
        return snippet
    except Exception as e:
        return f"// [Error reading file: {e}]"

def find_sarif_file(cwe_id: str):
    cwe_raw = cwe_id.strip().lower()
    if cwe_raw == "demo":
        sarif_folder = os.path.join(directory.SAST_RESULT_SARIF_DIR, "cwe-022")
    else:
        cwe_dir = f"cwe-{cwe_raw.zfill(3)}"
        sarif_folder = os.path.join(directory.SAST_RESULT_SARIF_DIR, cwe_dir)

    if not os.path.exists(sarif_folder):
        print(f"[!] Can't find directory SARIF: {sarif_folder}")
        return None
    for file in os.listdir(sarif_folder):
        if file.endswith(".sarif"):
            return os.path.join(sarif_folder, file)
    print(f"[!] Can't find file SARIF in: {sarif_folder}")
    return None

def parse_sarif_traces(sarif_path):
    with open(sarif_path, "r", encoding="utf-8") as f:
        sarif = json.load(f)

    result = {}
    for run in sarif.get("runs", []):
        for r in run.get("results", []):
            locs = r.get("locations", [])
            if not locs:
                continue
            physical = locs[0]["physicalLocation"]
            uri = physical["artifactLocation"]["uri"]
            line = physical["region"]["startLine"]
            class_name = uri.replace("/", ".").replace(".java", "").split(".")[-1]
            key = (class_name, line)

            steps = []
            for flow in r.get("codeFlows", []):
                for thread in flow.get("threadFlows", []):
                    for step in thread.get("locations", []):
                        loc = step.get("location", {})
                        msg = loc.get("message", {}).get("text", "").strip()
                        file = loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                        file = file.replace("/", ".").replace(".java", "")
                        step_line = loc.get("physicalLocation", {}).get("region", {}).get("startLine", "?")
                        if msg:
                            steps.append(f"{file}:{step_line} - {msg}")
                        else:
                            steps.append(f"{file}:{step_line}")
            result[key] = steps
    return result

def format_trace_steps(trace_list):
    if not trace_list:
        return "(omitted for brevity)"
    return "\n".join(f"{i+1}. {step}" for i, step in enumerate(trace_list))

def generate_prompts(cwe_id: str):
    cwe_id_raw = cwe_id.strip().lower()
    is_demo = (cwe_id_raw == "demo")
    cwe_id_zfill = cwe_id_raw if is_demo else cwe_id_raw.zfill(3)
    cwe_dir = f"cwe-{cwe_id_zfill}"
    cwe_full = f"CWE-{cwe_id_zfill}"
    hint = CWE_HINTS.get(cwe_id_zfill, "")

    sarif_path = find_sarif_file(cwe_id_raw)
    if not sarif_path:
        return
    sarif_traces = parse_sarif_traces(sarif_path)

    input_dir = os.path.join(directory.DAST_DIR, "gallet_result", cwe_dir)
    input_file = os.path.join(input_dir, f"{cwe_full}_Merged.csv")

    if not os.path.isfile(input_file):
        print(f"[!] Can't find required file: {input_file}")
        return

    print(f"[!] Using input: {input_file}")
    df = read_input_file(input_file)
    if "DAST" not in df.columns:
        print("[!] Missing DAST column in file.")
        return

    filtered = df[df["DAST"].astype(str).str.strip().str.lower() == "true"]
    output_dir = os.path.join(directory.LLM_DIR, "result", cwe_dir, "user_prompt_rs")
    os.makedirs(output_dir, exist_ok=True)

    for _, row in filtered.iterrows():
        src_expr = row.get("col2", "")
        snk_expr = row.get("col6", "")
        snk_cls = row.get("col4", "Unknown").split(".")[-1]
        snk_line = int(row.get("col7", 0))
        trace_key = (snk_cls, snk_line)
        trace_steps = sarif_traces.get(trace_key, [])

        intermediate = format_trace_steps(trace_steps)
        if intermediate == "(omitted for brevity)":
            print(f"[!] Can't find trace for: {snk_cls}:{snk_line}")

        src_code = extract_code_snippet(row.get("col0", ""), row.get("col3", 0), marker="// ← SOURCE")
        snk_code = extract_code_snippet(row.get("col4", ""), row.get("col7", 0), marker="// ← SINK")

        prompt_text = PROMPT_USER.format(
            cwe_description=cwe_full,
            cwe_id=cwe_full,
            hint=hint,
            source_msg=src_expr,
            source=f"```java\n{src_code}```",
            intermediate_steps=intermediate,
            sink_msg=snk_expr,
            sink=f"```java\n{snk_code}```"
        )

        filename = f"{snk_cls}.txt"
        with open(os.path.join(output_dir, filename), "w") as f:
            f.write(prompt_text)

    print(f"[!] Create {len(filtered)} prompt in: {output_dir}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create prompt for trigger alert")
    parser.add_argument("--cwe", required=True, help="CWE ID (ex: 022, 089, 078, demo)")
    args = parser.parse_args()
    generate_prompts(args.cwe)