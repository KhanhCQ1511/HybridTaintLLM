import argparse
import sys
import time
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import DAST_Module.script.instrument.galette_gen_user_prompt as galette_gen_user_prompt
import DAST_Module.script.instrument.galette_LLM_instrument as galette_LLM_instrument
import DAST_Module.script.instrument.galette_tagging_overwrite as galette_tagging_overwrite
import DAST_Module.script.propagation.galette_propagation as galette_propagation

def safe_run(step_name, func, cwe_id):
    try:
        func(cwe_id)
    except Exception as e:
        print(f"[!] [{step_name}] Error: {e}")
        sys.exit(1)

def dast_pipe(cwe_id: str):
    start_time = time.time()
    safe_run("[!] Generate User Prompt", galette_gen_user_prompt.generate_user_tagging_prompts, cwe_id)
    safe_run("[!] LLM Instrument", galette_LLM_instrument.run_prompts_for_cwe, cwe_id)
    safe_run("[!] Tagging Overwrite", galette_tagging_overwrite.process_all_llm_files, cwe_id)
    safe_run("[!] Propagation Test", galette_propagation.run_for_cwe, cwe_id)
    end_time = time.time()
    elapsed = end_time - start_time
    print(f"\n[!]Total DAST run time: {elapsed:.2f} second")
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DAST Module")
    parser.add_argument("--cwe", required=True, help="CWE ID (ex: 022, 078, 089)")
    args = parser.parse_args()

    dast_pipe(args.cwe)
