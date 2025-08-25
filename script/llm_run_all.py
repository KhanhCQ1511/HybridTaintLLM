import argparse
import sys
import time
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import LLM.script.generate_user_prompt as generate_user_prompt
import LLM.script.llm_triger_alert as llm_triger_alert

def safe_run(step_name, func, cwe_id):
    try:
        func(cwe_id)
    except Exception as e:
        print(f"[!] [{step_name}] Error: {e}")
        sys.exit(1)

def llm_pipe(cwe_id: str):
    start_time = time.time()
    safe_run("[!] Generate User Prompts", generate_user_prompt.generate_prompts, cwe_id)
    safe_run("[!] LLM Trigger Alert", llm_triger_alert.run_llm_on_prompts, cwe_id)
    end_time = time.time()
    elapsed = end_time - start_time
    print(f"\n[!]Total DAST run time: {elapsed:.2f} second")
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LLM Triger Alert")
    parser.add_argument("--cwe", required=True, help="CWE ID (ex: 022, 089, 078)")
    args = parser.parse_args()

    llm_pipe(args.cwe)
