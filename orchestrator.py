import os
import sys
import zipfile
import requests
import json
import subprocess
import time
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

MOBSF_URL = os.getenv("MOBSF_URL", "DEFAULT_URL")
API_KEY = os.getenv("MOBSF_API_KEY", "DEFAULT_KEY")
PROJECT_DIR = os.getenv("PROJECT_DIR", "App")
OUTPUT_ZIP = os.getenv("OUTPUT_DIR", "App.zip")


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
            files = {"file": (file_name, f, "application/zip")}
            response = requests.post(url, files=files, headers=headers, timeout=30)

        if response.status_code == 200:
            print("[+] Upload successful.")
            return response.json().get("hash")
        else:
            print(f"[-] Upload failed: {response.status_code} {response.text}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"[-] Network Error during upload: {e}")
        return None


def start_scan(file_hash):
    print("[*] Starting MobSF scan...")
    url = f"{MOBSF_URL}/api/v1/scan"
    data = {"hash": file_hash}
    headers = {"Authorization": API_KEY}

    try:
        response = requests.post(url, data=data, headers=headers, timeout=30)
        return response.status_code == 200
    except requests.exceptions.RequestException as e:
        print(f"[-] Network Error during scan: {e}")
        return False


def get_mobsf_json_report(file_hash):
    print("[*] Fetching MobSF JSON report...")
    url = f"{MOBSF_URL}/api/v1/report_json"
    data = {"hash": file_hash}
    headers = {"Authorization": API_KEY}

    try:
        response = requests.post(url, data=data, headers=headers, timeout=30)
        if response.status_code == 200:
            return response.json()
        return {}
    except requests.exceptions.RequestException as e:
        print(f"[-] Network Error fetching report: {e}")
        return {}


def run_swiftlint():
    print("[*] Running SwiftLint...")
    try:
        result = subprocess.run(["swiftlint", "lint", "--reporter", "json"], capture_output=True, text=True)
        return json.loads(result.stdout) if result.stdout else []
    except Exception as e:
        print(f"[-] SwiftLint execution error: {e}")
        return []


def run_semgrep():
    print("[*] Running Semgrep...")
    try:
        result = subprocess.run(["semgrep", "scan", "--json", "--config=auto"], capture_output=True, text=True)
        return json.loads(result.stdout) if result.stdout else {}
    except Exception as e:
        print(f"[-] Semgrep execution error: {e}")
        return {}


def generate_final_report(lint_data, semgrep_data, mobsf_data):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
    report_filename = f"SECURITY_REPORT_{timestamp}.md"

    print(f"[*] Generating Detailed Security Report: {report_filename}...")

    report_content = f"# Отчет по безопасности: {PROJECT_DIR}\n"
    report_content += f"Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"

    report_content += "## 1. SwiftLint\n"
    for issue in lint_data:
        report_content += f"- **{issue.get('reason')}** (`{issue.get('file')}:{issue.get('line')}`)\n"

    report_content += "\n## 2. Semgrep\n"
    for res in semgrep_data.get('results', []):
        report_content += f"- **{res['extra']['message']}** (`{res['path']}:{res['start']['line']}`)\n"

    report_content += "\n## 3. MobSF\n"
    findings = mobsf_data.get('findings', {}) if isinstance(mobsf_data, dict) else {}
    for key, value in findings.items():
        if isinstance(value, dict) and value.get('severity') in ['high', 'warning', 'critical']:
            report_content += f"- **{value.get('title')}** (Severity: {value.get('severity')})\n"

    with open(report_filename, "w", encoding="utf-8") as f:
        f.write(report_content)
    with open("FINAL_SECURITY_REPORT.md", "w", encoding="utf-8") as f:
        f.write(report_content)

    print(f"[+] Report saved to {report_filename}")


if __name__ == "__main__":
    try:
        print("=== Security Orchestration Started ===")

        if not os.path.exists(PROJECT_DIR):
            print(f"[-] Error: Directory {PROJECT_DIR} not found.")
            sys.exit(1)

        lint_results = run_swiftlint()
        semgrep_results = run_semgrep()

        create_zip(PROJECT_DIR, OUTPUT_ZIP)
        file_hash = upload_to_mobsf(OUTPUT_ZIP)

        if not file_hash:
            print("[-] Critical Error: Could not get file hash from MobSF.")
            sys.exit(1)

        if not start_scan(file_hash):
            print("[-] Critical Error: MobSF scan failed to start.")
            sys.exit(1)

        print("[*] Waiting for MobSF to process (15 seconds)...")
        time.sleep(15)

        mobsf_report = get_mobsf_json_report(file_hash)
        generate_final_report(lint_results, semgrep_results, mobsf_report)

        total_issues = len(lint_results) + len(semgrep_results.get('results', []))

        mobsf_findings = mobsf_report.get('findings', {}) if isinstance(mobsf_report, dict) else {}
        high_severity_count = sum(
            1 for v in mobsf_findings.values() if isinstance(v, dict) and v.get('severity') in ['high', 'critical'])
        total_issues += high_severity_count

        if total_issues > 0:
            print(f"\n[-] Vulnerabilities found: {total_issues}. Committing is prohibited.")
            print("[*] Check FINAL_SECURITY_REPORT.md for details.")
            sys.exit(1)

        print("\n[SUCCESS] Security check passed. No vulnerabilities found.")
        sys.exit(0)

    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")
        sys.exit(1)