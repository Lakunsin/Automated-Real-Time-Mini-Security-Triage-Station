# Automated-Real-Time-Mini-Security-Triage-Station

An EDR-style triage tool built on Ubuntu that monitors clipboard URLs and `~/Downloads` in real time, querying VirusTotal v3 and automatically deleting malicious files[cite: 2].

📄 **[Read Full Project Report (PDF)**

## Tech Stack
* Python 3 (`requests`, `pyperclip`, `watchdog`, `python-dotenv`)[cite: 2]
* Linux Utilities (`xclip`, `xsel`, `notify-send`)[cite: 2]
* VirusTotal v3 API[cite: 2]

## Quick Start
```bash
# 1. Install dependencies
sudo apt update && sudo apt install xclip xsel -y
pip3 install requests python-dotenv pyperclip watchdog

# 2. Add API key to .env
echo "VT_API_KEY=your_key_here" > .env

# 3. Run watchers
python3 clipboard_watcher.py
python3 downloads_monitor.py
```
