import os
import subprocess
from pathlib import Path
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
import directory

# Define paths
CODEQL_CLI = Path(directory.CODEQL_DIR) / "codeql"
SOURCE_ROOT = Path(directory.PROJECT_SOURCE_CODE_DIR)
DB_PATH = Path(directory.CODEQL_DB_PATH) / "BenchJavaDB"

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
