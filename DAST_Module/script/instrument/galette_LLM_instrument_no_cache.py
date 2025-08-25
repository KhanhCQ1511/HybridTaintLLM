import os
import sys
import csv
import time
import argparse
from datetime import datetime
from typing import List, Set

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))
from directory import GALETTE_INSTRUMENT_RESULTS
from DAST_Module.src.prompt_instrument import PROMPT_SYSTEM_TASK_TAGGING, FEW_SHOT_EXAMPLES
import LLM_secret as SECRET
from src.model.llm import create_model


def _ensure_dir(p: str) -> None:
    os.makedirs(p, exist_ok=True)


def _ensure_csv(csv_path: str) -> None:
    if not os.path.exists(csv_path):
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([
                "file", "start_time", "end_time", "elapsed_ms",
                "prompt_tokens", "output_tokens", "total_tokens",
                "api_key_suffix_or_backend"
            ])


def _candidate_cwe_folder_names(cwe_id: str) -> List[str]:
    raw = str(cwe_id).strip().lower()
    if raw == "demo":
        return ["cwe-demo"]
    if raw.isdigit():
        n = int(raw)
        candidates = [f"cwe-{raw}", f"cwe-{n:03d}", f"cwe-{n:04d}"]
        uniq, seen = [], set()
        for name in candidates:
            if name not in seen:
                uniq.append(name)
                seen.add(name)
        return uniq
    return [f"cwe-{raw}"]


def _canonical_cwe_folder_name(cwe_id: str) -> str:
    raw = str(cwe_id).strip().lower()
    if raw == "demo":
        return "cwe-demo"
    if raw.isdigit():
        n = int(raw)
        return f"cwe-{n:03d}"
    return f"cwe-{raw}"


def _find_existing_user_dirs(cwe_id: str) -> List[str]:
    base_user = os.path.join(GALETTE_INSTRUMENT_RESULTS, "user_prompt_rs")
    candidates = [os.path.join(base_user, fn) for fn in _candidate_cwe_folder_names(cwe_id)]
    return [p for p in candidates if os.path.isdir(p)]


def _process_one_dir(
    llm,
    user_prompt_dir: str,
    output_dir: str,
    metrics_csv: str,
    processed_filenames: Set[str],
) -> int:
    count = 0
    for file in sorted(os.listdir(user_prompt_dir)):
        if not file.endswith(".txt"):
            continue

        if file in processed_filenames:
            print(f"[skip] Duplicate filename '{file}' from {user_prompt_dir} (already processed earlier).")
            continue

        in_path = os.path.join(user_prompt_dir, file)
        out_path = os.path.join(output_dir, file)

        with open(in_path, "r", encoding="utf-8") as f:
            user_prompt = f.read()
        if not user_prompt.strip():
            print(f"[skip] Empty prompt file: {file}")
            continue

        start_iso = datetime.now().isoformat(timespec="seconds")
        t0 = time.perf_counter()

        text, key_suffix, usage = llm.invoke(
            PROMPT_SYSTEM_TASK_TAGGING,
            user_prompt,
            FEW_SHOT_EXAMPLES,
        )

        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(text)

        with open(metrics_csv, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([
                file, start_iso, datetime.now().isoformat(timespec="seconds"), elapsed_ms,
                usage.get("prompt_tokens"), usage.get("output_tokens"), usage.get("total_tokens"),
                key_suffix,
            ])

        print(f"[ok] Saved: {out_path}  ({elapsed_ms} ms)")
        processed_filenames.add(file)
        count += 1

    return count


def run_prompts_for_cwe(cwe_id: str, model_name: str) -> None:
    llm = create_model(model_name, temperature=0.0)

    user_dirs = _find_existing_user_dirs(cwe_id)
    if not user_dirs:
        base_user = os.path.join(GALETTE_INSTRUMENT_RESULTS, "user_prompt_rs")
        tried = ", ".join(_candidate_cwe_folder_names(cwe_id))
        print(f"[error] No matching folder found under '{base_user}'. Tried: {tried}")
        print("        Please verify the folder name or pass the matching --cwe value (e.g., 22 vs 022).")
        return

    canonical_folder = _canonical_cwe_folder_name(cwe_id)
    output_dir = os.path.join(GALETTE_INSTRUMENT_RESULTS, "LLM_prompt_rs", canonical_folder)
    _ensure_dir(output_dir)

    metrics_csv = os.path.join(output_dir, "metrics.csv")
    _ensure_csv(metrics_csv)

    print(f"[info] Will read from: {', '.join(user_dirs)}")
    print(f"[info] Will write to: {output_dir}")

    processed_filenames: Set[str] = set()
    total = 0
    for user_dir in user_dirs:
        total += _process_one_dir(llm, user_dir, output_dir, metrics_csv, processed_filenames)

    print(f"[done] {total} file(s) processed. Output folder: {output_dir}")
    print(f"[info] Metrics CSV: {metrics_csv}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LLM tagging without cache")
    parser.add_argument("--cwe", required=True, help="CWE ID (e.g., 22, 022, 089, or 'demo')")
    default_model = getattr(SECRET, "MODEL_NAME", "gemini-2.5-flash")
    parser.add_argument("--model", default=default_model,
                        help="Model, e.g., 'gemini-2.5-flash' or local 'ollama-deepseek-8b'/'ollama-gpt-oss'")
    args = parser.parse_args()
    run_prompts_for_cwe(args.cwe, model_name=args.model)