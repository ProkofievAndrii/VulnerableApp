import json
import os
import subprocess
import sys
import zipfile
import requests
from dotenv import load_dotenv

load_dotenv()

MOBSF_URL = os.getenv("MOBSF_URL", "DEFAULT_URL")
API_KEY = os.getenv("MOBSF_API_KEY", "DEFAULT_KEY")
PROJECT_DIR = os.getenv("PROJECT_DIR", "App")
OUTPUT_ZIP = os.getenv("OUTPUT_DIR", "App.zip")
OWASP_STANDARDIZATION = {
    "rules.hardcoded-api-key": "M1",
    "ios_hardcoded_info": "M1",
    "no_http_urls": "M5",
    "no_print_statements": "M9",
    "no_user_defaults": "M9",
    "rules.insecure-md5-hashing": "M10",
    "ios_swift_md5_collision": "M10",
    "colon": "M5/M9"
}


def create_zip(source_dir, output_filename):
    print(f"[*] Archiving {source_dir} for MobSF...")
    exclude_dirs = {'build', '.git', 'venv', 'DerivedData', 'xcuserdata', 'Tests'}

    with zipfile.ZipFile(output_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(source_dir):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            for file in files:
                if file.startswith('.') or file.endswith('.zip'):
                    continue
                file_path: str = str(os.path.join(root, file))
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
            response = requests.post(url, files=files, headers=headers)
        if response.status_code == 200:
            print("[+] Upload successful!")
            return response.json()["hash"]
        else:
            print(f"[-] Upload failed: {response.status_code}")
            return None
    except Exception as error:
        print(f"[-] Error during upload: {error}")
        return None


def start_scan(file_hash):
    print(f"[*] Starting Static Analysis for hash: {file_hash}...")
    url = f"{MOBSF_URL}/api/v1/scan"
    headers = {"Authorization": API_KEY}
    data = {"hash": file_hash}
    response = requests.post(url, data=data, headers=headers)
    return response.status_code == 200


def get_mobsf_json_report(file_hash):
    url = f"{MOBSF_URL}/api/v1/report_json"
    headers = {"Authorization": API_KEY}
    data = {"hash": file_hash}
    max_retries = 3
    for i in range(max_retries):
        print(f"[*] Fetching JSON report (Attempt {i + 1}/{max_retries})...")
        response = requests.post(url, data=data, headers=headers)
        if response.status_code == 200:
            report = response.json()
            if "code_analysis" in report:
                return report
        import time
        time.sleep(10)
    return {}


def run_swiftlint():
    print("[*] Running SwiftLint...")
    try:
        result = subprocess.run(
            ["swiftlint", "lint", "--config", "rules/swiftlint.yml", "--reporter", "json"],
            capture_output=True, text=True
        )
        return json.loads(result.stdout) if result.stdout else []
    except FileNotFoundError:
        print("[-] Error: SwiftLint is not installed or not in PATH. Install it via 'brew install swiftlint'.")
        return []
    except json.JSONDecodeError:
        print("[-] Error: Failed to parse SwiftLint output.")
        return []


def run_semgrep():
    print("[*] Running Semgrep...")
    try:
        result = subprocess.run(
            ["semgrep", "scan", "--config", "rules/semgrep_rules.yml", "--json", PROJECT_DIR],
            capture_output=True, text=True
        )
        return json.loads(result.stdout) if result.stdout else {}
    except FileNotFoundError:
        print("[-] Error: Semgrep is not installed or not in PATH.")
        return {}
    except json.JSONDecodeError:
        print("[-] Error: Failed to parse Semgrep output.")
        return {}


def get_code_snippet(file_path, line_number):
    try:
        full_path = file_path if os.path.exists(file_path) else os.path.join(os.getcwd(), file_path)
        with open(full_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            if 0 < line_number <= len(lines):
                return lines[line_number - 1].strip()
    except (FileNotFoundError, UnicodeDecodeError):
        return "Source code not available"
    return "Line not found"


def generate_final_report(lint_data, semgrep_data, mobsf_data):
    from datetime import datetime

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
    report_filename = f"SECURITY_REPORT_{timestamp}.md"
    print(f"[*] Generating Detailed Security Report: {report_filename}...")

    mobsf_findings = mobsf_data.get('code_analysis', {}).get('findings', {})

    m_issues = []
    for key, finding in mobsf_findings.items():
        metadata = finding.get('metadata', {})
        if metadata.get('severity') in ['high', 'warning']:
            m_issues.append((key, finding))

    report_content = "# Detailed Security Analysis Report\n"
    report_content += f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"

    report_content += "## 1. Executive Summary\n\n"
    report_content += f"- **SwiftLint Issues:** {len(lint_data)}\n"
    report_content += f"- **Semgrep Issues:** {len(semgrep_data.get('results', []))}\n"
    report_content += f"- **MobSF Issues:** {len(m_issues)}\n\n"

    report_content += "## 2. Detailed Findings\n\n"
    report_content += "---\n\n"

    for issue in lint_data:
        file_path = issue['file']
        line = issue['line']
        code_snippet = get_code_snippet(file_path, line)
        rule_id = issue.get('rule_id', 'N/A')
        severity = issue.get('severity', 'Unknown')
        rule_type = issue.get('type', 'N/A')
        character = issue.get('character', '0')

        category = OWASP_STANDARDIZATION.get(rule_id, "M5/M9")

        report_content += f"### [{category}] {issue['reason']}\n\n"
        report_content += f"- **Tool:** SwiftLint\n"
        report_content += f"- **Severity:** {severity}\n"
        report_content += f"- **Rule ID:** {rule_id}\n"
        report_content += f"- **Type:** {rule_type}\n"
        report_content += f"- **File:** `{file_path}` (Line: {line}, Char: {character})\n"
        report_content += f"- **Code:** `{code_snippet}`\n"
        report_content += f"- **Message:** {issue['reason']}\n\n"
        report_content += "---\n\n"

    for finding in semgrep_data.get('results', []):
        file_path = finding['path']
        line = finding['start']['line']
        col = finding['start'].get('col', '0')
        code_snippet = get_code_snippet(file_path, line)

        extra = finding.get('extra', {})
        msg = extra.get('message', 'No message')
        severity = extra.get('severity', 'UNKNOWN')
        check_id = finding.get('check_id', 'N/A')

        category = OWASP_STANDARDIZATION.get(check_id, "M1/M10")

        report_content += f"### [{category}] {check_id}\n\n"
        report_content += f"- **Tool:** Semgrep\n"
        report_content += f"- **Severity:** {severity}\n"
        report_content += f"- **Rule ID:** {check_id}\n"
        report_content += f"- **File:** `{file_path}` (Line: {line}, Col: {col})\n"
        report_content += f"- **Code:** `{code_snippet}`\n"
        report_content += f"- **Message:** {msg}\n\n"
        report_content += "---\n\n"

    for key, finding in m_issues:
        metadata = finding.get('metadata', {})
        desc = metadata.get('description', 'No description')
        severity = metadata.get('severity', 'unknown').upper()
        files_dict = finding.get('files', {})

        cvss = metadata.get('cvss', 'N/A')
        cwe = metadata.get('cwe', 'N/A')
        masvs = metadata.get('masvs', 'N/A')
        ref = metadata.get('ref', '#')

        category = OWASP_STANDARDIZATION.get(key, "M7/M8")

        files_str = ", ".join([f"{f} (Lines: {l})" for f, l in files_dict.items()])
        if not files_str:
            files_str = "N/A"

        report_content += f"### [{category}] {key}\n\n"
        report_content += f"- **Tool:** MobSF (Static Analysis)\n"
        report_content += f"- **Severity:** {severity} (CVSS Score: {cvss})\n"
        report_content += f"- **CWE:** {cwe}\n"
        report_content += f"- **MASVS:** {masvs}\n"
        report_content += f"- **File:** `{files_str}`\n"
        report_content += f"- **Description:** {desc}\n"
        report_content += f"- **Reference:** [View Documentation]({ref})\n\n"
        report_content += "---\n\n"

    for f_path in [report_filename, "FINAL_SECURITY_REPORT.md"]:
        with open(f_path, "w", encoding='utf-8') as f:
            f.write(report_content)

    return len(m_issues)


if __name__ == "__main__":
    try:
        print("=== Security Orchestration Started ===")
        lint_results = run_swiftlint()
        semgrep_results = run_semgrep()

        if os.path.exists(PROJECT_DIR):
            create_zip(PROJECT_DIR, OUTPUT_ZIP)
        else:
            print(f"[-] Error: Directory {PROJECT_DIR} not found.")
            sys.exit(1)

        file_hash = upload_to_mobsf(OUTPUT_ZIP)
        if file_hash:
            if start_scan(file_hash):
                mobsf_report = get_mobsf_json_report(file_hash)
                m_count = generate_final_report(lint_results, semgrep_results, mobsf_report)

                total_issues = len(lint_results) + len(semgrep_results.get('results', [])) + m_count
                if total_issues > 0:
                    print(f"\n[-] Found vulnerabilities: {total_issues}. Commit/Push is prohibited.")
                    sys.exit(1)

                print("\n[SUCCESS] No vulnerabilities found.")
                sys.exit(0)
            else:
                print("[-] MobSF scan failed to start.")
                sys.exit(1)
        else:
            print("[-] Could not get file hash from MobSF.")
            sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)
