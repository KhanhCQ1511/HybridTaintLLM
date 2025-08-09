"""
A script for processing input prompts and sending them to Gemini API for analysis.

This script processes text prompts corresponding to a CWE (Common Weakness Enumeration) ID, sends them
to the Gemini API, decodes any output received as JSON, and saves the results to an output directory. It also
logs the performance of API calls for later analysis and computes basic statistics on durations. A valid API
key and model configuration are required to trigger the Gemini API.

Functions:
- call_gemini_api: Sends a system and user prompt to the configured Gemini API and retrieves the response.
- extract_json_from_text: Extracts a JSON object from a text string, if present.
- run_llm_on_prompts: Orchestrates processing of input prompt files and handles API communications, JSON validation,
  result storage, and performance recording.
"""

import os
import sys
import json
import argparse
import time
import glob
import re
import csv
import google.generativeai as genai
import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
import directory
from LLM.src.prompt import PROMPT_SYSTEM_TASK
from LLM_secret import GEMINI_KEY, MODEL_NAME

def call_gemini_api(system_prompt: str, user_prompt: str) -> str:
        genai.configure(api_key=GEMINI_KEY)
        model = genai.GenerativeModel(MODEL_NAME)
        full_prompt = f"{system_prompt}\n\n{user_prompt}"
        response = model.generate_content(full_prompt)
        return response.text

def extract_json_from_text(text: str):
    try:
        match = re.search(r'{[\s\S]*}', text)
        if match:
            return json.loads(match.group())
    except json.JSONDecodeError:
        pass
    return None

def run_llm_on_prompts(cwe_id: str):
    cwe_id = cwe_id.zfill(3)
    cwe_dir = f"cwe-{cwe_id}"
    input_dir = os.path.join(directory.LLM_DIR, "result", cwe_dir, "user_prompt_rs")
    output_dir = os.path.join(directory.LLM_DIR, "result", cwe_dir, "LLM_prompt_rs")
    os.makedirs(output_dir, exist_ok=True)

    prompt_files = glob.glob(os.path.join(input_dir, "*.txt"))
    if not prompt_files:
        print(f"[!] Can't find file prompt in: {input_dir}")
        return

    print(f"[!] Processing {len(prompt_files)} prompt from {input_dir}")

    total_start_time = time.time()
    perf_log = []

    for file_path in prompt_files:
        file_name = os.path.basename(file_path)
        out_path = os.path.join(output_dir, file_name.replace(".txt", ".json"))

        if os.path.exists(out_path):
            print(f"[!] Exist: {file_name} → Skip")
            continue

        with open(file_path, "r", encoding="utf-8") as f:
            user_prompt = f.read()

        print(f"[!] Sending: {file_name} ...")
        start_time = time.time()
        output = call_gemini_api(PROMPT_SYSTEM_TASK, user_prompt)
        duration = round(time.time() - start_time, 2)

        if not output:
            print(f"[!] No response for: {file_name}")
            perf_log.append([file_name, duration])
            continue

        try:
            parsed = json.loads(output)
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(parsed, f, indent=2)
            print(f"[!] Save JSON: {out_path}")
            perf_log.append([file_name, duration])
            time.sleep(1.5)
            continue
        except json.JSONDecodeError:
            pass

        extracted = extract_json_from_text(output)
        if extracted:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(extracted, f, indent=2)
            print(f"[!] Extracted JSON from text and saved: {out_path}")
            perf_log.append([file_name, duration])
        else:
            fallback_data = {
                "raw_output": output,
                "note": "[!] Not valid JSON. Manual check required."
            }
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(fallback_data, f, indent=2)
            print(f"Write raw output to JSON: {out_path}")
            perf_log.append([file_name, duration])

        time.sleep(1.5)

    total_duration = round(time.time() - total_start_time, 2)

    perf_csv = os.path.join(output_dir, f"performance_cwe{cwe_id}.csv")
    run_idx = 1

    if os.path.exists(perf_csv):
        df = pd.read_csv(perf_csv)
        while f"Duration (s) Run {run_idx}" in df.columns:
            run_idx += 1
    else:
        df = pd.DataFrame({"Prompt File": [row[0] for row in perf_log]})

    curr_result = {row[0]: row[1] for row in perf_log}
    df.set_index("Prompt File", inplace=True)
    df[f"Duration (s) Run {run_idx}"] = pd.Series(curr_result)
    df.reset_index(inplace=True)

    df.to_csv(perf_csv, index=False, encoding="utf-8-sig")

    valid_durations = [d for d in curr_result.values() if isinstance(d, (int, float))]
    if valid_durations:
        avg_duration = round(sum(valid_durations) / len(valid_durations), 2)
        print(f"\n[!] Processed {len(valid_durations)} prompt.")
        print(f"[!] Average time per prompt: {avg_duration} seconds")
    else:
        print("\n[!] No valid time data available")

    print(f"[!] Total CWE execution time-{cwe_id}: {total_duration} seconds")
    print(f"[!] Performance log saved at: {perf_csv}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Using Gemini to trigger alert")
    parser.add_argument("--cwe", required=True, help="CWE ID (ex: 022, 078, 089)")
    args = parser.parse_args()
    run_llm_on_prompts(args.cwe)
