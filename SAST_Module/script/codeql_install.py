import os
import sys
import requests
import zipfile
import io
import shutil

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
import directory

GITHUB_API_URL = "https://api.github.com/repos/github/codeql-cli-binaries/releases/latest"

def download_and_extract_codeql():
    print("[!] Checking latest CodeQL release from GitHub...")
    response = requests.get(GITHUB_API_URL)
    response.raise_for_status()
    release_data = response.json()

    linux_asset = next((a for a in release_data.get("assets", []) if "linux64.zip" in a["name"]), None)
    if not linux_asset:
        raise Exception("[!] Can't find codeql-linux64.zip in latest release.")

    download_url = linux_asset["browser_download_url"]
    print(f"[!] Downloading CodeQL from: {download_url}")

    r = requests.get(download_url)
    r.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(r.content)) as zip_ref:
        if os.path.exists(directory.CODEQL_DIR):
            print("[!] Removing old CodeQL directory...")
            shutil.rmtree(directory.CODEQL_DIR)
        print(f"[!] Extracting to: {directory.CODEQL_DIR}")
        zip_ref.extractall(directory.CODEQL_DIR)

    print("[!] CodeQL has been successfully installed at:", directory.CODEQL_DIR)

if __name__ == "__main__":
    try:
        download_and_extract_codeql()
    except Exception as e:
        print(f"Error: {e}")
