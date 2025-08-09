"""
This module processes the output of an LLM to overwrite Java source files with tagged code blocks.
The module allows parsing tagged code blocks from text files, locating the corresponding Java files in the filesystem,
and overwriting them with the extracted code. It provides functionality to process multiple files associated with
specific CWE (Common Weakness Enumeration) IDs.

Functions:
- parse_llm_output: Parses code blocks and metadata from LLM output text files.
- clean_code_block: Cleans up extracted code blocks for formatting consistency.
- find_java_file: Searches Java files in a directory tree based on their name.
- apply_tagged_code: Overwrites Java source files with tagged code extracted from the LLM output.
- process_all_llm_files: Main function to scan a directory for text files, extract code blocks, and apply tagged code.
"""

import os
import re
import argparse
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))
from directory import PROJECT_SOURCE_CODE_JAVA_DIR, GALETTE_INSTRUMENT_RESULTS_LLM

# parse data out of LLM
def parse_llm_output(llm_file):
    with open(llm_file, "r", encoding="utf-8") as f:
        content = f.read()

    blocks = []

    # Source and sink in one files
    one_file_pattern = r"Source & Sink File:\s*(.+?)\n```java\n(.*?)```"
    for file_name, code in re.findall(one_file_pattern, content, re.DOTALL):
        blocks.append({"file_name": file_name.strip(), "code": code.strip()})

    # Source and sink in difference files
    multi_file_pattern = r"(Source|Sink) File:\s*(.+?)\n```java\n(.*?)```"
    for file_type, file_name, code in re.findall(multi_file_pattern, content, re.DOTALL):
        blocks.append({"file_name": file_name.strip(), "code": code.strip()})

    return blocks

# clean output
def clean_code_block(code: str) -> str:
    code = code.rstrip()
    code = re.sub(r"<>\s*$", "", code)
    return code

# find java files
def find_java_file(file_name):
    for root, dirs, files in os.walk(PROJECT_SOURCE_CODE_JAVA_DIR):
        if file_name in files:
            return os.path.join(root, file_name)
    return None

#  Overwrite the original Java source files with the tagged code from LLM output
def apply_tagged_code(parsed_blocks):
    for block in parsed_blocks:
        file_name = block["file_name"]
        new_code = clean_code_block(block["code"])

        java_file_path = find_java_file(file_name)

        if not java_file_path:
            print(f"[!] File: {file_name} not found in directory tree")
            continue

        with open(java_file_path, "w", encoding="utf-8") as f:
            f.write(new_code + "\n")

        print(f"[!] Overwritten file: {java_file_path}")

# main class
def process_all_llm_files(cwe_id):
    cwe_dir = os.path.join(GALETTE_INSTRUMENT_RESULTS_LLM, f"cwe-{str(cwe_id).zfill(3)}")
    if not os.path.exists(cwe_dir):
        raise FileNotFoundError(f"[!] Directory not found for CWE-{cwe_id}: {cwe_dir}")

    txt_files = [f for f in os.listdir(cwe_dir) if f.endswith(".txt")]
    if not txt_files:
        raise FileNotFoundError(f"[!] No .txt files found in {cwe_dir}")

    print(f"[!] Scanning {len(txt_files)} files in directory: {cwe_dir}")
    for txt_file in txt_files:
        txt_path = os.path.join(cwe_dir, txt_file)
        print(f"\n[!] Processing file: {txt_file}")

        blocks = parse_llm_output(txt_path)
        if not blocks:
            print(f"[!] No code block found in {txt_file}")
            continue

        print(f"[!] Found {len(blocks)} code blocks in {txt_file}")
        apply_tagged_code(blocks)

# entry point
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Overwrite code from LLM output into Java source code")
    parser.add_argument("--cwe", required=True, help="CWE ID, ví dụ: 22")
    args = parser.parse_args()
    process_all_llm_files(args.cwe)

