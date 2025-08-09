import os
import sys
import json
import csv
import argparse

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from directory import ROOT_DIR, GALETTE_INSTRUMENT_RESULTS, LLM_DIR

COST_INPUT = 0.000018
COST_OUTPUT = 0.000036
CHARS_PER_TOKEN = 4

# Estimate token count from text length (chars per token)
def count_tokens(text):
    return max(1, len(text) // CHARS_PER_TOKEN)

# Read input/output files, count tokens for each file name
def get_tokens(user_dir, output_dir):
    input_tokens, output_tokens = {}, {}

    if os.path.isdir(user_dir):
        for file in os.listdir(user_dir):
            if file.endswith(".txt") or file.endswith(".java"):
                with open(os.path.join(user_dir, file), encoding="utf-8") as f:
                    input_tokens[os.path.splitext(file)[0]] = count_tokens(f.read())

    if os.path.isdir(output_dir):
        for file in os.listdir(output_dir):
            ext = os.path.splitext(file)[1].lower()
            filepath = os.path.join(output_dir, file)
            if ext == ".json":
                with open(filepath, encoding="utf-8") as f:
                    data = json.load(f)
                    parts = []
                    if "explanation" in data:
                        parts.append(data["explanation"])
                    if "fix_suggestion" in data:
                        if "summary" in data["fix_suggestion"]:
                            parts.append(data["fix_suggestion"]["summary"])
                        code = data["fix_suggestion"].get("code")
                        if isinstance(code, list):
                            for item in code:
                                if isinstance(item, str):
                                    parts.append(item)
                                elif isinstance(item, dict):
                                    for v in item.values():
                                        if isinstance(v, str):
                                            parts.append(v)
                    output_tokens[os.path.splitext(file)[0]] = count_tokens("\n".join([str(x) for x in parts]))
            elif ext in [".java", ".txt"]:
                with open(filepath, encoding="utf-8") as f:
                    output_tokens[os.path.splitext(file)[0]] = count_tokens(f.read())
    return input_tokens, output_tokens

# Write token counts and cost per file into a CSV report
def write_csv(path, input_tokens, output_tokens):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    names = sorted(set(input_tokens) | set(output_tokens))
    total_in = sum(input_tokens.get(n, 0) for n in names)
    total_out = sum(output_tokens.get(n, 0) for n in names)
    total_cost = total_in * COST_INPUT + total_out * COST_OUTPUT
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Name", "Input Tokens", "Output Tokens", "Total Cost (USD)"])
        for name in names:
            inp = input_tokens.get(name, 0)
            out = output_tokens.get(name, 0)
            cost = inp * COST_INPUT + out * COST_OUTPUT
            writer.writerow([name, inp, out, f"{cost:.6f}"])
        writer.writerow([])
        writer.writerow(["TOTAL", total_in, total_out, f"{total_cost:.6f}"])

# Evaluate token usage for a module and save CSV report
def eval_module(user_dir, output_dir, save_path, label):
    input_tokens, output_tokens = get_tokens(user_dir, output_dir)
    if not input_tokens and not output_tokens:
        print(f"[!] No data found for {label}: {user_dir} / {output_dir}")
        return
    write_csv(save_path, input_tokens, output_tokens)
    print(f"[+] {label} token info saved to {save_path}")

# main function
def main():
    parser = argparse.ArgumentParser(description="Calculate token/cost for DAST and LLM Trigger per CWE")
    parser.add_argument("--cwe", required=True, help="CWE id, e.g. 22, 078, 089")
    args = parser.parse_args()
    cwe_id = args.cwe.zfill(3)
    cwe_dir = f"cwe-{cwe_id}"
    eval_dir = os.path.join(ROOT_DIR, "eval/result", cwe_dir)

    # DAST
    dast_user = os.path.join(GALETTE_INSTRUMENT_RESULTS, "user_prompt_rs", cwe_dir)
    dast_llm = os.path.join(GALETTE_INSTRUMENT_RESULTS, "LLM_prompt_rs", cwe_dir)
    dast_csv = os.path.join(eval_dir, f"Token_DAST_CWE-{cwe_id}.csv")

    # LLM Trigger
    llm_user = os.path.join(LLM_DIR, "result", cwe_dir, "user_prompt_rs")
    llm_llm = os.path.join(LLM_DIR, "result", cwe_dir, "LLM_prompt_rs")
    llm_csv = os.path.join(eval_dir, f"Token_LLM_CWE-{cwe_id}.csv")

    eval_module(dast_user, dast_llm, dast_csv, "DAST")
    eval_module(llm_user, llm_llm, llm_csv, "LLM Trigger")

# entry point
if __name__ == "__main__":
    main()
