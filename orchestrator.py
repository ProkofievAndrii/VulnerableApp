import os
import zipfile
import requests
import json
import subprocess

# --- CONFIG ---
MOBSF_URL = "http://localhost:8000"
API_KEY = "1a122a63777930dc140128532b169071c12c99b2e8e34b33c5d505d4c9f35c67"
PROJECT_DIR = "SecurityTestApp"
OUTPUT_ZIP = "SecurityTestApp.zip"

def create_zip(source_dir, output_filename):
    print(f"[*] Archiving {source_dir}...")
    with zipfile.ZipFile(output_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(source_dir):
            for file in files:
                if not any(x in root for x in ['build', '.git', 'xcuserdata']):
                    zipf.write(os.path.join(root, file))
    print(f"[+] Archive created: {output_filename}")

def upload_to_mobsf(file_path):
    print("[*] Uploading to MobSF API...")
    url = f"{MOBSF_URL}/api/v1/upload"
    headers = {"Authorization": API_KEY}
    files = {"file": open(file_path, "rb")}
    
    response = requests.post(url, files=files, headers=headers)
    if response.status_code == 200:
        print("[+] Upload successful!")
        return response.json()["hash"]
    else:
        print(f"[-] Upload failed: {response.text}")
        return None

def start_scan(file_hash):
    print(f"[*] Starting Static Analysis for hash: {file_hash}...")
    url = f"{MOBSF_URL}/api/v1/scan"
    headers = {"Authorization": API_KEY}
    data = {"hash": file_hash}
    
    response = requests.post(url, data=data, headers=headers)
    if response.status_code == 200:
        print("[+] Scan initiated successfully.")
        return True
    return False

def get_mobsf_json_report(file_hash):
    print("[*] Fetching JSON report...")
    url = f"{MOBSF_URL}/api/v1/report_json"
    headers = {"Authorization": API_KEY}
    data = {"hash": file_hash}
    
    response = requests.post(url, data=data, headers=headers)
    return response.json()

def run_swiftlint():
    print("[*] Running SwiftLint...")
    result = subprocess.run(
        ["swiftlint", "lint", "--config", "rules/swiftlint.yml", "--reporter", "json"],
        capture_output=True, text=True
    )
    return json.loads(result.stdout) if result.stdout else []

def run_semgrep():
    print("[*] Running Semgrep...")
    result = subprocess.run(
        ["semgrep", "scan", "--config", "rules/semgrep_rules.yml", "--json", PROJECT_DIR],
        capture_output=True, text=True
    )
    return json.loads(result.stdout) if result.stdout else {}

if __name__ == "__main__":
    lint_results = run_swiftlint()
    semgrep_results = run_semgrep()
    
    create_zip(PROJECT_DIR, OUTPUT_ZIP)
    file_hash = upload_to_mobsf(OUTPUT_ZIP)
    
    if file_hash:
        if start_scan(file_hash):
            mobsf_report = get_mobsf_json_report(file_hash)
            print("[+] All scans completed!")