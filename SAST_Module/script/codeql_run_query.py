"""
This script executes CodeQL queries for given CWEs, processes the output to generate
CSV files, and handles them, including optional merging for specific scenarios.

The script uses command-line arguments to specify a CWE ID, runs queries
mapped to that CWE, decodes results, and outputs them in a specified format. It supports
merging results from multiple CSV files where necessary, with specialized handling
for specific CWEs.

Functions:
- run_query: Executes a single CodeQL query and decodes the result into a CSV format.
- merge_csv_files: Combines multiple CSV files into a single output CSV.
- run_and_merge_queries: Executes all queries, merges the decoded output, and stores results in a combined CSV for specific CWEs.
- run_for_cwe(cwe_id): Main function to orchestrate query execution for a specified CWE ID from the command line argument.
"""

import os
import sys
import argparse
import subprocess
from pathlib import Path
import csv
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
import directory

QUERY_ROOT = Path(directory.CODEQL_QUERY)
DB_PATH = Path(directory.CODEQL_DB_PATH) / "BenchJavaDB"
RESULT_ROOT = Path(directory.ROOT_DIR) / "SAST_Module" / "ql_results"
CODEQL = Path(directory.CODEQL_DIR) / "codeql"
CWE_DIRS = {"022": "cwe-022", "078": "cwe-078", "089": "cwe-089"}

# Run a CodeQL query and decode the result to CSV
def run_query(query_path: Path, db_path: Path, result_csv_path: Path):
    result_csv_path.parent.mkdir(parents=True, exist_ok=True)
    bqrs_file = result_csv_path.with_suffix(".bqrs")

    print(f"[!] Running query: {query_path.name}")
    start_time = time.time()

    subprocess.run([
        str(CODEQL), "query", "run", str(query_path),
        "--database", str(db_path),
        "--output", str(bqrs_file)
    ], check=True)

    subprocess.run([
        str(CODEQL), "bqrs", "decode", str(bqrs_file),
        "--format=csv",
        "--output", str(result_csv_path)
    ], check=True)

    end_time = time.time()
    duration = end_time - start_time

    print(f"[!] Output saved: {result_csv_path}")
    print(f"[!] Query time: {duration:.2f} seconds\n")
    return duration

# Merge multiple CSV files into a single output CSV.
def merge_csv_files(csv_paths, output_path):
    header_written = False
    with open(output_path, 'w', newline='') as fout:
        writer = None
        for csv_file in csv_paths:
            with open(csv_file, 'r') as fin:
                reader = csv.reader(fin)
                rows = list(reader)
                if not rows:
                    continue
                header, data = rows[0], rows[1:]
                if not header_written:
                    writer = csv.writer(fout)
                    writer.writerow(header)
                    header_written = True
                writer.writerows(data)
    print(f"[!] Combined CSV written to {output_path}")

# Special handler for cwe-078: run all queries and merge CSVs
def run_and_merge_queries(query_files, result_dir, cwe_folder):
    combined_csvs = []
    total_duration = 0.0
    for query_file in sorted(query_files):
        temp_csv = result_dir / f"{query_file.stem}.csv"
        duration = run_query(query_file, DB_PATH, temp_csv)
        total_duration += duration
        combined_csvs.append(temp_csv)
    merged_csv = result_dir / "combined.csv"
    merge_csv_files(combined_csvs, merged_csv)
    for temp in combined_csvs:
        temp.unlink()
    print(f"[!] Output saved: {merged_csv}")
    print(f"[!] Total time for {cwe_folder}: {total_duration:.2f} seconds\n")

# main
def run_for_cwe(cwe_id):
    """Main logic to run CodeQL queries for the given CWE ID (as string, e.g., '022')."""
    cwe_folder = CWE_DIRS.get(cwe_id)
    if not cwe_folder:
        print(f"[!] Invalid CWE ID: {cwe_id}. Allowed: {list(CWE_DIRS.keys())}")
        return

    query_dir = QUERY_ROOT / cwe_folder
    result_dir = RESULT_ROOT / cwe_folder
    result_dir.mkdir(parents=True, exist_ok=True)

    if not query_dir.exists():
        print(f"[!] Query directory not found: {query_dir}")
        return

    query_files = list(query_dir.glob("*.ql"))
    if not query_files:
        print(f"[!] No .ql files found in {query_dir}")
        return

    if not DB_PATH.exists():
        print(f"[!] CodeQL database not found: {DB_PATH}")
        return

    print(f"\n[!] Running queries for {cwe_folder}")

    if cwe_id == "078":
        run_and_merge_queries(query_files, result_dir, cwe_folder)
    else:
        for query_file in sorted(query_files):
            result_csv = result_dir / f"{query_file.stem}.csv"
            run_query(query_file, DB_PATH, result_csv)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run CodeQL query for CWE")
    parser.add_argument("--cwe", required=True, help="CWE ID (ex: 022, 078, 089)")
    args = parser.parse_args()
    run_for_cwe(args.cwe)