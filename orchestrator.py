import json
import os
import subprocess
import sys
import zipfile
import requests
import tempfile
from dotenv import load_dotenv
from owasp_mapping import OWASP_STANDARDIZATION

load_dotenv()

MOBSF_URL = os.getenv("MOBSF_URL", "DEFAULT_URL")
API_KEY = os.getenv("MOBSF_API_KEY", "DEFAULT_KEY")
PROJECT_DIR = os.getenv("PROJECT_DIR", "App")
OUTPUT_ZIP = os.getenv("OUTPUT_DIR", "App.zip")
PACKAGE_ID = os.getenv("PACKAGE_ID", "App")


def prepare_vulnerable_app():
    print("[*] Preparing VulnerableApp: Building and Installing...")
    workspace_path = os.path.join(PROJECT_DIR, "SecurityTestApp.xcworkspace")

    if not os.path.exists(workspace_path):
        print(f"    [-] Error: Workspace not found at {workspace_path}. Maybe 'pod install'")
        return False

    build_dir = os.path.abspath("build_output")

    try:
        subprocess.run([
            "xcodebuild", "-workspace", workspace_path,
            "-scheme", "SecurityTestApp",
            "-configuration", "Debug",
            "-sdk", "iphonesimulator",
            "-destination", "platform=iOS Simulator,name=iPhone 16 Pro",
            f"SYMROOT={build_dir}",
            "clean", "build"
        ], check=True, capture_output=True)

        app_path = os.path.join(build_dir, "Debug-iphonesimulator", "SecurityTestApp.app")
        print("    [*] Installing fresh build to simulator...")
        subprocess.run(["xcrun", "simctl", "install", "booted", app_path], check=True, capture_output=True)

        print("    [*] Application successfully built and installed.")
        return True
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.decode('utf-8', errors='ignore') if e.stderr else str(e)
        print(f"    [-] Error: Build/Install failed. {error_msg}")
        return False


def create_zip(source_dir, output_filename):
    print(f"[*] Archiving {source_dir} for MobSF...")
    exclude_dirs = {'build', '.git', 'venv', 'DerivedData', 'xcuserdata', 'Tests', 'Pods', '.build', 'Carthage'}

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
            print("    [*] Uploaded successfully")
            return response.json()["hash"]
        else:
            print(f"[-] Error: Upload failed. {response.status_code}")
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
        print(f"    [*] Fetching JSON report (Attempt {i + 1}/{max_retries})...")
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
        print("    [-] Error: SwiftLint is not installed or not in PATH.")
        return []
    except json.JSONDecodeError:
        print("    [-] Error: Failed to parse SwiftLint output.")
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
        print("    [-] Error: Semgrep is not installed or not in PATH.")
        return {}
    except json.JSONDecodeError:
        print("    [-] Error: Failed to parse Semgrep output.")
        return {}


def run_dependency_check():
    print("[*] Running OWASP Dependency-Check...")
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_file:
        temp_path = tmp_file.name

    base_args = [
        "dependency-check",
        "--project", PROJECT_DIR,
        "--scan", PROJECT_DIR,
        "--format", "JSON",
        "--out", temp_path,
        "--disableYarnAudit",
        "--disableNodeAudit",
        "--enableExperimental"
    ]

    try:
        print("    [*] Attempting to update vulnerability database...")
        result = subprocess.run(base_args, capture_output=True, text=True)

        if result.returncode != 0:
            print("    [-] Network error or update failed. Retrying in --noupdate mode...")
            offline_args = base_args + ["--noupdate"]
            result = subprocess.run(offline_args, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"    [-] ODC Execution Error: {result.stderr[:500].strip()}")

        if os.path.exists(temp_path) and os.path.getsize(temp_path) > 0:
            with open(temp_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data

        print("    [-] Error: No report generated by dependency-check.")
        return {}

    except FileNotFoundError:
        print("    [-] Error: dependency-check command not found in system PATH.")
        return {}
    except json.JSONDecodeError:
        print("    [-] Error: Failed to parse Dependency-Check JSON output.")
        return {}
    except Exception as err:
        print(f"    [-] Unexpected error during ODC scan: {err}")
        return {}
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def get_code_snippet(file_path, line_number):
    try:
        full_path = file_path if os.path.exists(file_path) else os.path.join(os.getcwd(), file_path)
        with open(full_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            if 0 < line_number <= len(lines):
                return lines[line_number - 1].strip()
    except (FileNotFoundError, UnicodeDecodeError):
        return "Error: Source code not available"
    return "Error: Line not found"


def run_memory_leak_check(package_name):
    print(f"[*] Running Direct RAM Scanner...")
    dump_results = []

    try:
        result = subprocess.run(
            ["python3", "tools/fast_scanner.py", package_name],
            capture_output=True, text=True, check=True
        )

        for line in result.stdout.splitlines():
            if line.startswith("VULN_FOUND:"):
                warning = line.replace("VULN_FOUND:", "").strip()
                if warning not in dump_results:
                    dump_results.append(warning)
                    # print(f"    [!] VERIFIED IN RAM: {warning}")

    except subprocess.CalledProcessError as e:
        print(f"    [-] Error: Fast scanner failed. Exit code: {e.returncode}")
        if e.stdout: print(e.stdout.strip())
        if e.stderr: print(e.stderr.strip())

    return dump_results


def run_sandbox_check(package_id):
    print(f"[*] Running Sandbox Inspection for {package_id}...")
    sandbox_issues = []

    try:
        result = subprocess.run(
            ["xcrun", "simctl", "get_app_container", "booted", package_id, "data"],
            capture_output=True, text=True, check=True
        )
        container_path = result.stdout.strip()

        target_file = os.path.join(container_path, "Documents", "credentials.txt")

        if os.path.exists(target_file):
            # print(f"    [!] FOUND: Sensitive file discovered at {target_file}")

            with open(target_file, "r", encoding="utf-8") as f:
                content = f.read()
                if "super_secret_password" in content or "secret" in content.lower():
                    issue = "    [M9] Plaintext credentials found in Sandbox (credentials.txt)"
                    sandbox_issues.append(issue)
                    # print(f"    [!] VERIFIED: Plaintext password found in file!")
        else:
            print("    [*] No insecure credentials file found in Documents.")

    except subprocess.CalledProcessError:
        print("    [-] Error: Could not retrieve app container path.")

    return sandbox_issues


def generate_final_report(lint_data, semgrep_data, mobsf_data, odc_data, dynamic_data):
    from datetime import datetime

    mobsf_findings = mobsf_data.get('code_analysis', {}).get('findings', {})
    m_issues = []
    for key, finding in mobsf_findings.items():
        metadata = finding.get('metadata', {})
        if metadata.get('severity') in ['high', 'warning']:
            m_issues.append((key, finding))

    odc_issues = []
    for dep in odc_data.get('dependencies', []):
        file_name = dep.get('fileName', 'Unknown')
        for vuln in dep.get('vulnerabilities', []):
            odc_issues.append({
                'file': file_name,
                'cve': vuln.get('name', 'N/A'),
                'severity': vuln.get('severity', 'UNKNOWN'),
                'description': vuln.get('description', 'No description')
            })

    semgrep_issues = semgrep_data.get('results', [])
    total = len(lint_data) + len(semgrep_issues) + len(odc_issues) + len(m_issues) + len(dynamic_data)

    critical_findings = "## CRITICAL & HIGH Risk\n\n---\n\n"
    minor_findings = "## Warnings & Best Practices\n\n---\n\n"

    for finding in dynamic_data:
        res = f"### {finding}\n\n"
        res += f"- **Tool:** RAM/Sandbox Scanner\n"
        res += f"- **Status:** VERIFIED IN RUNTIME\n"
        res += f"- **Description:** Sensitive data extracted directly from the application process or sandbox during execution.\n\n---\n\n"
        critical_findings += res

    for finding in semgrep_issues:
        file_path = finding['path']
        line = finding['start']['line']
        col = finding['start'].get('col', '0')
        code_snippet = get_code_snippet(file_path, line)
        extra = finding.get('extra', {})
        msg = extra.get('message', 'No message')
        severity = extra.get('severity', 'UNKNOWN')
        check_id = finding.get('check_id', 'N/A')
        category = OWASP_STANDARDIZATION.get(check_id, "M1/M10")

        res = f"### [{category}] {check_id}\n\n"
        res += f"- **Tool:** Semgrep\n"
        res += f"- **Severity:** {severity}\n"
        res += f"- **Rule ID:** {check_id}\n"
        res += f"- **File:** `{file_path}` (Line: {line}, Col: {col})\n"
        res += f"- **Code:** `{code_snippet}`\n"
        res += f"- **Message:** {msg}\n\n---\n\n"

        if severity.upper() == "ERROR":
            critical_findings += res
        else:
            minor_findings += res

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
        files_str = ", ".join([f"{f} (Lines: {l})" for f, l in files_dict.items()]) or "N/A"

        res = f"### [{category}] {key}\n\n"
        res += f"- **Tool:** MobSF (Static Analysis)\n"
        res += f"- **Severity:** {severity} (CVSS Score: {cvss})\n"
        res += f"- **CWE:** {cwe}\n"
        res += f"- **MASVS:** {masvs}\n"
        res += f"- **File:** `{files_str}`\n"
        res += f"- **Description:** {desc}\n"
        res += f"- **Reference:** [View Documentation]({ref})\n\n---\n\n"

        if severity == "HIGH":
            critical_findings += res
        else:
            minor_findings += res

    for issue in odc_issues:
        res = f"### [M2] {issue['cve']} in {issue['file']}\n\n"
        res += f"- **Tool:** OWASP Dependency-Check\n"
        res += f"- **Severity:** {issue['severity']}\n"
        res += f"- **File:** `{issue['file']}`\n"
        res += f"- **Description:** {issue['description']}\n\n---\n\n"

        if issue['severity'].upper() in ["HIGH", "CRITICAL"]:
            critical_findings += res
        else:
            minor_findings += res

    for issue in lint_data:
        file_path = issue['file']
        line = issue['line']
        code_snippet = get_code_snippet(file_path, line)
        rule_id = issue.get('rule_id', 'N/A')
        severity = issue.get('severity', 'Unknown')
        rule_type = issue.get('type', 'N/A')
        character = issue.get('character', '0')
        category = OWASP_STANDARDIZATION.get(rule_id, "M5/M9")

        res = f"### [{category}] {issue['reason']}\n\n"
        res += f"- **Tool:** SwiftLint\n"
        res += f"- **Severity:** {severity}\n"
        res += f"- **Rule ID:** {rule_id}\n"
        res += f"- **Type:** {rule_type}\n"
        res += f"- **File:** `{file_path}` (Line: {line}, Char: {character})\n"
        res += f"- **Code:** `{code_snippet}`\n"
        res += f"- **Message:** {issue['reason']}\n\n---\n\n"
        minor_findings += res

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
    report_filename = f"SECURITY_REPORT_{timestamp}.md"

    report_header = "# Detailed Security Analysis Report\n"
    report_header += f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    report_header += f"**Total Vulnerabilities Found:** {total}\n\n"
    report_header += "## 1. Executive Summary\n\n"
    report_header += f"- **SwiftLint Issues:** {len(lint_data)}\n"
    report_header += f"- **Semgrep Issues:** {len(semgrep_issues)}\n"
    report_header += f"- **OWASP Dependency-Check Issues:** {len(odc_issues)}\n"
    report_header += f"- **MobSF Issues:** {len(m_issues)}\n"
    report_header += f"- **Dynamic Analysis (Memory/Sandbox) Issues:** {len(dynamic_data)}\n\n"
    report_header += "## 2. Detailed Findings\n\n"

    final_content = report_header + critical_findings + minor_findings

    for f_path in [report_filename, "FINAL_SECURITY_REPORT.md"]:
        with open(f_path, "w", encoding='utf-8') as f:
            f.write(final_content)

    return total


if __name__ == "__main__":
    try:
        print("=== Security Orchestration Started ===")

        if not prepare_vulnerable_app():
            print("    [-] Could not deploy app.")
            sys.exit(1)

        lint_results = run_swiftlint()
        semgrep_results = run_semgrep()
        odc_results = run_dependency_check()

        mobsf_report = {}
        if os.path.exists(PROJECT_DIR):
            create_zip(PROJECT_DIR, OUTPUT_ZIP)
            file_hash = upload_to_mobsf(OUTPUT_ZIP)
            if file_hash:
                if start_scan(file_hash):
                    mobsf_report = get_mobsf_json_report(file_hash)
                else:
                    print("    [-] Error: MobSF scan failed to start. Skipping MobSF.")
            else:
                print("    [-] Error: Could not get file hash from MobSF. Skipping MobSF.")
        else:
            print(f"    [-] Error: Directory {PROJECT_DIR} not found. Skipping MobSF.")

        frida_results = []
        print(f"[*] Starting target application {PACKAGE_ID} via simctl...")
        process_result = subprocess.run(["xcrun", "simctl", "launch", "booted", PACKAGE_ID], capture_output=True)

        if process_result.returncode == 0:
            import time

            time.sleep(10)

            frida_results = run_memory_leak_check(PROJECT_DIR)
            sandbox_results = run_sandbox_check(PACKAGE_ID)
            dynamic_results = frida_results + sandbox_results

            subprocess.run(["xcrun", "simctl", "terminate", "booted", PACKAGE_ID], capture_output=True)
        else:
            print("    [-] Error: Failed to launch app in simulator. Skipping dynamic memory analysis.")

        total_vulnerabilities = generate_final_report(lint_results, semgrep_results, mobsf_report, odc_results,
                                                      dynamic_results)

        if total_vulnerabilities > 0:
            print(f"\n[-] Found vulnerabilities: {total_vulnerabilities}. Commit/Push is prohibited.")
            sys.exit(1)

        print("\n[SUCCESS] No vulnerabilities found.")
        sys.exit(0)

    except Exception as e:
        print(f"    [-] Error: {e}")
        sys.exit(1)
