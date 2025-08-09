"""
This script processes CWE-related user prompts and generates responses using an LLM model. The resulting
responses are saved to an output directory. It uses the Google Gemini API for content generation.

Functions:
- call_gemini: Sends a system and user prompt to the LLM model and retrieves the generated response.
- run_prompts_for_cwe: Processes all prompts related to a specific CWE ID and saves the responses.
"""

import os
import sys
import argparse
import google.generativeai as genai # type: ignore

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))
from directory import GALETTE_INSTRUMENT_RESULTS
from DAST_Module.src.prompt_instrument import PROMPT_SYSTEM_TASK_TAGGING
from LLM_secret import GEMINI_KEY, MODEL_NAME

# call gemini
def call_gemini(system_prompt, user_prompt):
    genai.configure(api_key=GEMINI_KEY)
    model = genai.GenerativeModel(MODEL_NAME)
    combined_prompt = f"{system_prompt}\n\n{user_prompt}"
    response = model.generate_content(combined_prompt)
    return response.text

# run prompt for cwe
def run_prompts_for_cwe(cwe_id):
    cwe_id = str(cwe_id).zfill(3)
    user_prompt_dir = os.path.join(GALETTE_INSTRUMENT_RESULTS, "user_prompt_rs", f"cwe-{cwe_id}")
    output_dir = os.path.join(GALETTE_INSTRUMENT_RESULTS, "LLM_prompt_rs", f"cwe-{cwe_id}")

    if not os.path.exists(user_prompt_dir):
        print(f"[!] Can't not find directory for CWE-{cwe_id}: {user_prompt_dir}")
        return

    os.makedirs(output_dir, exist_ok=True)
    total = 0

    for file in os.listdir(user_prompt_dir):
        if not file.endswith(".txt"):
            continue

        user_prompt_path = os.path.join(user_prompt_dir, file)
        with open(user_prompt_path, "r", encoding="utf-8") as f:
            user_prompt = f.read()

        print(f"[!] Sending prompt: {file}")
        try:
            output_text = call_gemini(PROMPT_SYSTEM_TASK_TAGGING, user_prompt)
        except Exception as e:
            print(f"[!] Error sending file {file}: {e}")
            continue

        # Output
        output_path = os.path.join(output_dir, file)
        with open(output_path, "w", encoding="utf-8") as out_f:
            out_f.write(output_text)

        print(f"[!] Save in: {output_path}")
        total += 1

    print(f"\n[!] Success! Processed {total} file prompt for CWE-{cwe_id}.")

# entry point
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Using LLM to tagging")
    parser.add_argument("--cwe", required=True, help="CWE ID (ex: 022, 078, 089)")
    args = parser.parse_args()
    run_prompts_for_cwe(args.cwe)
