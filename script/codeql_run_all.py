"""
Static Application Security Testing (SAST) pipeline execution module.

This module implements the workflow for creating a CodeQL database, running
CodeQL queries for a given CWE (Common Weakness Enumeration) identifier, and
measuring the total execution time. It provides a command-line interface to
trigger the SAST process with the required CWE ID.

Functions:
- safe_run: Safely executes a step in the pipeline, catching and reporting errors during its execution.
- sast_pipe(cwe_id): Executes the complete SAST pipeline for a given CWE ID.
"""

import argparse
import sys
import time
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from SAST_Module.script.codeql_create_db import create_codeql_db
from SAST_Module.script.codeql_run_query import run_for_cwe

def safe_run(step_name, func, *args, **kwargs):
    try:
        func(*args, **kwargs)
    except Exception as e:
        print(f"[!] [{step_name}] Error: {e}")
        sys.exit(1)

def sast_pipe(cwe_id: str):
    start_time = time.time()
    safe_run("[!] Create CodeQL DB", create_codeql_db)
    safe_run(f"[!] Run CodeQL Query for CWE-{cwe_id}", run_for_cwe, f"cwe-{cwe_id}")
    end_time = time.time()
    elapsed = end_time - start_time
    print(f"\n[!] Total SAST run time: {elapsed:.2f} seconds")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SAST Pipeline")
    parser.add_argument("--cwe", required=True, help="CWE ID (ex: 022, 078, 089)")
    args = parser.parse_args()
    sast_pipe(args.cwe)
