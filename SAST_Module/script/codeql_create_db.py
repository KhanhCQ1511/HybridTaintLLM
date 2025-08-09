"""
A script for creating a single CodeQL database for Java code analysis.

This script automates the creation of a CodeQL database from source code
using the CodeQL CLI. It validates the presence of required directories and
executables before initiating the database creation process. The database
is created only if all prerequisites are met.

Functions:
- create_codeql_db: Creates a CodeQL database for Java source code analysis.
"""

import os
import subprocess
from pathlib import Path
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from directory import CODEQL_DIR, PROJECT_SOURCE_CODE_DIR, CODEQL_DB_PATH
CODEQL_CLI = Path(CODEQL_DIR) / "codeql"
SOURCE_ROOT = Path(PROJECT_SOURCE_CODE_DIR)
DB_PATH = Path(CODEQL_DB_PATH) / "BenchJavaDB"

# create databases
def create_codeql_db():
    if not CODEQL_CLI.exists():
        print(f"[!] CodeQL CLI not found: {CODEQL_CLI}")
        return

    if not SOURCE_ROOT.exists():
        print(f"[!] Source code directory not found: {SOURCE_ROOT}")
        return

    print(f"[!] Creating single CodeQL database for: {SOURCE_ROOT}")
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    try:
        subprocess.run([
            str(CODEQL_CLI), "database", "create", str(DB_PATH),
            "--language=java",
            "--source-root", str(SOURCE_ROOT)
        ], check=True)
        print(f"[!] CodeQL DB created at: {DB_PATH}")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to create database: {e}")

if __name__ == "__main__":
    create_codeql_db()
