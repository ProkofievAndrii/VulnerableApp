import os
import sys
import zipfile
import requests
import json
import subprocess
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# --- CONFIG ---
MOBSF_URL = os.getenv("MOBSF_URL", "http://localhost:8000")
API_KEY = os.getenv("MOBSF_API_KEY", "1a122a63777930dc140128532b169071c12c99b2e8e34b33c5d505d4c9f35c67")
PROJECT_DIR = "SecurityTestApp"
OUTPUT_ZIP = "SecurityTestApp.zip"


def create_zip(source_dir, output_filename):
    print(f"[*] Archiving {source_dir} for MobSF...")
    with zipfile.ZipFile(output_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(source_dir):
            if any(x in root for x in ['build', '.git', 'venv', 'DerivedData', 'xcuserdata']):
                continue
            for file in files:
                if file.startswith('.'):
                    continue

                file_path = os.path.join(root, file)
                archive_name = os.path.relpath(file_path, source_dir)
                zipf.write(file_path, archive_name)


def upload_to_mobsf(file_path):
    print("[*] Uploading to MobSF API...")
    url = f"{MOBSF_URL}/api/v1/upload"
    headers = {"Authorization": API_KEY}

    file_name = os.path.basename(file_path)

    try:
        with open(file_path, "rb") as f:
            files = {
                "file": (file_name, f, "application/zip")
            }
            response = requests.post(url, files=files, headers=headers)

        if response.status_code == 200:
            print("[+] Upload successful!")
            return response.json()["hash"]
        else:
            print(f"[-] Upload failed: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"[-] Error during upload: {e}")
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


def get_code_snippet(file_path, line_number):
    try:
        if not os.path.exists(file_path):
            full_path = os.path.join(os.getcwd(), file_path)
        else:
            full_path = file_path

        with open(full_path, 'r') as f:
            lines = f.readlines()
            if 0 < line_number <= len(lines):
                return lines[line_number - 1].strip()
    except Exception:
        return "Source code not available"
    return "Line not found"


def generate_final_report(lint_data, semgrep_data, mobsf_data):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
    report_filename = f"SECURITY_REPORT_{timestamp}.md"

    print(f"[*] Generating Detailed Security Report: {report_filename}...")

    report_content = "# Detailed Security Analysis Report\n"
    report_content += f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"

    report_content += "## 1. Executive Summary\n"
    report_content += f"- **SwiftLint Issues:** {len(lint_data)}\n"
    report_content += f"- **Semgrep Issues:** {len(semgrep_data.get('results', []))}\n\n"

    report_content += "## 2. Detailed Findings\n"
    report_content += "---\n"

    for issue in lint_data:
        file_path = issue['file']
        line = issue['line']
        code_snippet = get_code_snippet(file_path, line)
        category = "M5/M9" if "OWASP" not in issue['reason'] else issue['reason'].split('(')[1].split(')')[0]

        report_content += f"### [{category}] {issue['reason']}\n"
        report_content += f"- **Tool:** SwiftLint\n"
        report_content += f"- **File:** `{file_path}` (Line: {line})\n"
        report_content += f"- **Code:** `{code_snippet}`\n"
        report_content += f"- **Message:** {issue['reason']}\n\n"
        report_content += "---\n"

    for finding in semgrep_data.get('results', []):
        file_path = finding['path']
        line = finding['start']['line']
        code_snippet = get_code_snippet(file_path, line)
        msg = finding['extra']['message']
        category = "M1/M10" if "OWASP" not in msg else msg.split('(')[1].split(')')[0]

        report_content += f"### [{category}] {finding['check_id']}\n"
        report_content += f"- **Tool:** Semgrep\n"
        report_content += f"- **File:** `{file_path}` (Line: {line})\n"
        report_content += f"- **Code:** `{code_snippet}`\n"
        report_content += f"- **Message:** {msg}\n\n"
        report_content += "---\n"

    with open(report_filename, "w") as f:
        f.write(report_content)
    with open("FINAL_SECURITY_REPORT.md", "w") as f:
        f.write(report_content)

    print(f"[+] Report saved to {report_filename}")


if __name__ == "__main__":
    try:
        print("=== Security Orchestration Started ===")

        lint_results = run_swiftlint()
        semgrep_results = run_semgrep()

        if os.path.exists(PROJECT_DIR):
            create_zip(PROJECT_DIR, OUTPUT_ZIP)
        else:
            print(f"[-] Error: Directory {PROJECT_DIR} not found.")
            exit(1)

        file_hash = upload_to_mobsf(OUTPUT_ZIP)

        if file_hash:
            if start_scan(file_hash):
                import time
                print("[*] Waiting for MobSF to process...")
                time.sleep(10)

                mobsf_report = get_mobsf_json_report(file_hash)
                generate_final_report(lint_results, semgrep_results, mobsf_report)

                total_issues = len(lint_results) + len(semgrep_results.get('results', []))

                if total_issues > 0:
                    print(f"\n[-] Found vulnerabilities: {total_issues}. Commit/Push is prohibited.")
                    print("[*] Refer to FINAL_SECURITY_REPORT.md for details.")
                    sys.exit(1)

                print("\n[SUCCESS] Security check passed. No vulnerabilities found.")
                sys.exit(0)
            else:
                print("[-] Critical Error: MobSF scan failed to start.")
                sys.exit(1)
        else:
            print("[-] Critical Error: Could not get file hash from MobSF.")

    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")