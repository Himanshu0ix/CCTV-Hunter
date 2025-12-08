#!/bin/bash

echo "[*] Updating system..."
if command -v apt >/dev/null 2>&1; then
    sudo apt update && sudo apt install -y python3 python3-pip git
elif command -v pkg >/dev/null 2>&1; then
    pkg update && pkg install -y python git python-pip
fi

echo "[*] Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "[*] Installation complete."
echo "Run the tool with: python3 cctv_scanner.py"
