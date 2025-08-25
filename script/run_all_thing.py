import argparse
import sys
import time
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from SAST_Module.script.codeql_run_query import run_queries_for_cwe
from DAST_Module.script.instrument.galette_gen_user_prompt import generate_user_tagging_prompts
from DAST_Module.script.instrument.galette_LLM_instrument_no_cache import run_prompts_for_cwe as run_no_cache
from DAST_Module.script.instrument.galette_LLM_instrument_cache import run_prompts_for_cwe as run_cache
from DAST_Module.script.instrument.galette_tagging_overwrite import process_all_llm_files
from DAST_Module.script.propagation.galette_propagation import run_for_cwe
from LLM.script.generate_user_prompt import generate_prompts
from LLM.script.llm_triger_alert_no_cache import run_llm_on_prompts

def safe_run(step_name, func, *args, **kwargs):
    try:
        print(f"[+] Starting: {step_name}")
        func(*args, **kwargs)
        print(f"[+] Finished: {step_name}\n")
    except Exception as e:
        print(f"[!] [{step_name}] Error: {e}")
        sys.exit(1)

def run_full_pipeline(cwe_id: str, model: str, use_cache: bool):
    total_start = time.time()
    is_demo = cwe_id.strip().lower() == "demo"
    model_lower = model.strip().lower()

    if use_cache and "gemini" not in model_lower:
        print(f"[!] Cache mode only supported for Gemini models. Your model: {model}")
        sys.exit(1)

    sast_start = time.time()
    safe_run(f"Run CodeQL Query for CWE-{cwe_id}", run_queries_for_cwe, f"cwe-{cwe_id}")
    sast_end = time.time()
    print(f"[!] SAST (CodeQL) phase time: {sast_end - sast_start:.2f}s\n")

    dast_start = time.time()
    safe_run("Generate User Prompt (Galette)", generate_user_tagging_prompts, cwe_id)
    if use_cache:
        safe_run("LLM Instrument (Galette, Cache)", run_cache, cwe_id, model)
    else:
        safe_run("LLM Instrument (Galette, No Cache)", run_no_cache, cwe_id, model)
    safe_run("Tagging Overwrite (Galette)", process_all_llm_files, cwe_id)
    safe_run("Propagation Test (Galette)", run_for_cwe, cwe_id)
    dast_end = time.time()
    print(f"[!] DAST (Galette) phase time: {dast_end - dast_start:.2f}s\n")

    llm_start = time.time()
    safe_run("Generate User Prompts (LLM)", generate_prompts, cwe_id)
    llm_end = time.time()
    print(f"[!] LLM phase time: {llm_end - llm_start:.2f}s\n")

    total_end = time.time()
    print(f"[!] TOTAL PIPELINE TIME: {total_end - total_start:.2f}s")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SAST + DAST + LLM Pipeline")
    parser.add_argument("--cwe", required=True, help="CWE ID (ex: 022, 078, 089, or 'demo')")
    parser.add_argument("--model", required=True, help="LLM model name (e.g. gemini-2.5-flash, ollama-qwen-8b)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--cache", action="store_true", help="Use LLM instrument with cache (Gemini only)")
    group.add_argument("--nocache", action="store_true", help="Use LLM instrument without cache")
    args = parser.parse_args()
    run_full_pipeline(args.cwe.strip().lower(), args.model.strip(), args.cache)
