#!/bin/bash

echo "[*] Starting system deployment..."

# 1. Homebrew
if ! command -v brew &> /dev/null; then
    echo "[!] Homebrew not found. Please install it first from https://brew.sh"
    exit 1
fi

# 2. Dependencies
echo "[*] Installing SwiftLint and Semgrep via Homebrew..."
brew install swiftlint semgrep

# 3. Python environment
echo "[*] Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
if [ -f requirements.txt ]; then
    pip install -r requirements.txt
else
    pip install requests
    pip freeze > requirements.txt
fi

# 4. Docker setup for MobSF
if ! command -v docker &> /dev/null; then
    echo "[!] Docker not found. Please install Docker Desktop to run MobSF."
else
    echo "[*] Pulling MobSF Docker image..."
    docker pull opensecurity/mobile-security-framework-mobsf:latest
fi

echo "[+] Deployment complete! To start, run: source venv/bin/activate"