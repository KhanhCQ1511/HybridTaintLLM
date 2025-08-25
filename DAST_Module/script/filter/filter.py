import os
import sys
import argparse
import csv
import re
from typing import Iterable, Set, List, Tuple

try:
    import directory  # type: ignore
except Exception:
    here = os.path.abspath(os.path.dirname(__file__))
    for up in range(1, 6):
        cand = os.path.abspath(os.path.join(here, *([".."] * up)))
        if cand not in sys.path:
            sys.path.insert(0, cand)
        try:
            import directory  # type: ignore  # noqa: E402
            break
        except Exception:
            continue
    else:
        raise SystemExit("[!] Could not import module 'directory'. Place this script inside the project and ensure 'directory.py' exists at the repo root.")

try:
    QL_RESULTS_ROOT = directory.CODEQL_REUSLT
    OUTPUT_ROOT     = directory.GALETTE_FILTER
except AttributeError as e:
    raise SystemExit(f"[!] Missing variable in directory.py: {e}. Required: CODEQL_REUSLT and GALETTE_FILTER.")

def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def cwe_folder(cwe_id: int) -> str:
    return f"cwe-{cwe_id:03d}"

def find_csvs(root: str) -> Iterable[str]:
    for base, _, files in os.walk(root):
        for f in files:
            if f.lower().endswith(".csv"):
                yield os.path.join(base, f)

def extract_filename_from_col4(col4: str) -> str:
    s = (col4 or "").strip()
    if not s:
        return ""
    if s.endswith(".java"):
        return os.path.basename(s)
    if "." in s and ("/" not in s and "\\" not in s):
        short = s.split(".")[-1]
        return f"{short}.java"
    base = os.path.basename(s)
    if base and "." not in base:
        return base + ".java"
    return os.path.basename(s)

def classify_cwe22(col6: str) -> Tuple[bool, bool]:
    v = (col6 or "").strip().lower()
    to_string = ("filename" in v) or ("new file" in v)
    to_list   = ("filetarget" in v) or ("path" in v)
    return to_string, to_list

def classify_cwe78(col6: str) -> Tuple[bool, bool]:
    raw = (col6 or "").strip()
    v = raw.lower()
    to_list   = ("argsenv" in v) or bool(re.search(r"\bargs\b", raw)) or ("arglist" in v)
    to_string = ("+" in raw)
    return to_string, to_list

def classify_cwe89(col6: str) -> Tuple[bool, bool]:
    return True, False

def read_csv_rows(path: str) -> Iterable[List[str]]:
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            yield row

def collect_from_csv(csv_path: str, cwe: int,
                     bag_string: Set[str], bag_list: Set[str]) -> None:
    it = read_csv_rows(csv_path)
    header = next(it, None)
    if not header:
        return
    name_to_idx = {name.strip().lower(): i for i, name in enumerate(header)}
    idx_col4 = name_to_idx.get("col4", 4)
    idx_col6 = name_to_idx.get("col6", 6)
    for row in it:
        if len(row) <= max(idx_col4, idx_col6):
            continue
        col4 = (row[idx_col4] or "").strip()
        col6 = (row[idx_col6] or "").strip()
        if not col4 or col4.lower() in {"col4", "file", "source expression"}:
            continue
        name = extract_filename_from_col4(col4)
        if cwe == 22:
            to_string, to_list = classify_cwe22(col6)
        elif cwe == 78:
            to_string, to_list = classify_cwe78(col6)
        elif cwe == 89:
            to_string, to_list = classify_cwe89(col6)
        else:
            return
        if to_string and name:
            bag_string.add(name)
        if to_list and name:
            bag_list.add(name)

def write_out(out_dir: str, string_names: Set[str], list_names: Set[str], cwe: int) -> None:
    ensure_dir(out_dir)
    string_path = os.path.join(out_dir, "string_gr.txt")
    list_path   = os.path.join(out_dir, "list_gr.txt")
    with open(string_path, "w", encoding="utf-8") as f:
        for n in sorted(string_names):
            f.write(f"{n}\n")
    if cwe in (22, 78):
        with open(list_path, "w", encoding="utf-8") as f:
            for n in sorted(list_names):
                f.write(f"{n}\n")
    else:
        open(list_path, "w", encoding="utf-8").close()

def main():
    parser = argparse.ArgumentParser(description="Split files by column 6 and write normalized file names from column 4 (.java).")
    parser.add_argument("--cwe", type=int, choices=[22, 78, 89], required=True, help="Choose 22, 78, or 89")
    args = parser.parse_args()
    in_dir  = os.path.join(QL_RESULTS_ROOT, cwe_folder(args.cwe))
    out_dir = os.path.join(OUTPUT_ROOT,     cwe_folder(args.cwe))
    ensure_dir(in_dir)
    ensure_dir(out_dir)
    csv_files = list(find_csvs(in_dir))
    if not csv_files:
        print(f"[!] No CSV found in: {in_dir}")
        write_out(out_dir, set(), set(), args.cwe)
        return
    bag_string: Set[str] = set()
    bag_list: Set[str]   = set()
    for p in csv_files:
        try:
            collect_from_csv(p, args.cwe, bag_string, bag_list)
        except Exception as e:
            print(f"[!] Error reading {p}: {e}")
    write_out(out_dir, bag_string, bag_list, args.cwe)
    print(f"[✓] CWE-{args.cwe:03d}:")
    print(f"    - string_gr.txt: {len(bag_string)} items -> {os.path.join(out_dir, 'string_gr.txt')}")
    if args.cwe in (22, 78):
        print(f"    - list_gr.txt  : {len(bag_list)} items -> {os.path.join(out_dir, 'list_gr.txt')}")
    else:
        print("    - CWE-089: only string_gr.txt is created")

if __name__ == "__main__":
    main()
