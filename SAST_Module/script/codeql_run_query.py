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

# Chạy truy vấn CodeQL
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

# Gộp file CSV
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

# Giữ lại 5 dòng đầu tiên
def keep_only_top_rows(csv_path: Path, num_rows: int = 5):
    with open(csv_path, "r") as fin:
        rows = list(csv.reader(fin))
    if len(rows) <= 1:
        return
    header, data = rows[0], rows[1:num_rows+1]
    with open(csv_path, "w", newline="") as fout:
        writer = csv.writer(fout)
        writer.writerow(header)
        writer.writerows(data)
    print(f"[!] Trimmed to first {num_rows} rows: {csv_path}")

# Chạy truy vấn theo thư mục CWE
def run_queries_for_cwe(query_folder: str, result_folder: str, is_demo: bool = False):
    query_dir = QUERY_ROOT / query_folder
    result_dir = RESULT_ROOT / result_folder
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

    if query_folder == "cwe-078":
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
        print(f"[!] Total time for {query_folder}: {total_duration:.2f} seconds\n")
    else:
        for query_file in sorted(query_files):
            result_csv = result_dir / f"{query_file.stem}.csv"
            run_query(query_file, DB_PATH, result_csv)
            if is_demo:
                keep_only_top_rows(result_csv, 5)

# MAIN
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run CodeQL queries for CWE")
    parser.add_argument("-f", "--filter", help="Specify CWE folder (e.g., cwe-022 or 'demo')")
    args = parser.parse_args()

    cwe_dirs = ["cwe-022", "cwe-078", "cwe-089"]
    is_demo = False

    if args.filter == "demo":
        print("\n[!] Running in DEMO mode (cwe-022 queries, 5 rows only)")
        run_queries_for_cwe(query_folder="cwe-022", result_folder="cwe-demo", is_demo=True)

    elif args.filter:
        if args.filter not in cwe_dirs:
            print(f"[!] Invalid CWE: {args.filter}")
            sys.exit(1)
        run_queries_for_cwe(query_folder=args.filter, result_folder=args.filter)

    else:
        for cwe in cwe_dirs:
            print(f"\n[!] Running queries for {cwe}")
            run_queries_for_cwe(query_folder=cwe, result_folder=cwe)