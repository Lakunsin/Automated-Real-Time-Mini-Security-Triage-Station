# Automated-Real-Time-Mini-Security-Triage-Station

**Technical Project Report: Automated Real-Time Mini-Security Triage Station**

By: Lakunsin

Entry-Level Cybersecurity Analyst

July 2026

**Executive Summary**

This report documents the design, implementation, and refinement of an automated Mini-Security Triage Station deployed within a Linux environment (Ubuntu VM). The system provides Security Operations Center (SOC) style real-time analysis by bridging local OS telemetry with the Virustotal v3 API. By combining automated clipboard monitoring (xclip + Regex optimization) and real-time filesystem observation (watchdog), the triage station instantly checks copied URLs/domains and newly downloaded files against global threat intelligence databases, utilizing desktop notifications (notify-send) and an automated quarantine/deletion policy for verified malicious files.

---

**System Architecture**

This triage station relies on a combination of native Linux utilities, configuration files, and Python scripts working together:

·       **Clipboard Utility (xclip)**: A lightweight background Linux tool that allows the system to read clipboard memory. It spies on copied text so that links or domains can be automatically processed.

·       **Desktop Notification Tool (notify-send)**: A native Linux utility that generates instant desktop pop-up alerts. This is used to immediately inform the user of VirusTotal scan results without needing the terminal open.

·       **Secure Configuration File (.env)**: A hidden file used to store the private VirusTotal API key. This keeps sensitive credentials secure and separate from the source code.

·       **Python Dependencies:**

- **pyperclip**: Allows Python to interact directly with the clipboard.
- **requests**: Used to send and retrieve data from the VirusTotal API.
- **python-dotenv**: Enables Python to securely read credentials from the .env file.
- **watchdog**: Monitors the target directory for filesystem changes.

·       **The Scanning Core (scanner.py)**: The engine of the project. It handles the communication with VirusTotal, analyses URLs and file hashes, coordinates desktop notifications, and executes the auto-deletion logic.

·       **The Clipboard Watcher (clipboard_watcher.py):** A background script that continually checks the clipboard, uses a regular expression to extract URLs or naked domains and forwards them to the scanner.

·       **The Directory Observer (downloads_monitor.py)**: A background script that watches the local _~/Downloads folder_. The moment a new file is fully written to the disk, it triggers the scanning core to evaluate the file's hash.

**Phase 1: Automated Clipboard Monitoring with VirusTotal API**

**Step 1: Installing the Linux Clipboard Utility (xclip)**

To allow the background process to monitor clipboard memory and capture copied URL/links, install the lightweight clipboard manager xclip

Open the terminal and run this command to install it:
```bash
```
**sudo apt update**

**sudo apt install xclip -y**
```
```

![Image](./Screenshots/1xclip_install.png)

**Step 2: Installing the Desktop Notification Tool (notify-send)**

To display scan alerts on your screen in real time without relying on an open terminal window, verify that your system is equipped with notify-send

Run this command:
```bash
```
**notify-send "SOC Triage Station" "Testing desktop notification system..."**
```
```

![Image](./Screenshots/2popup_tool.png)

**Step 3: Create a Fresh Project Directory**

To keep the triage system organized, a dedicated project directory is created:

Run this command to create the folder and move inside it:
```bash
```
**mkdir -p ~/security_triage**

**cd ~/security_triage**
```
```
(Verify that your terminal prompt changes to show ~/security_triage before moving forward.)

![Image](./Screenshots/3Fresh_directory.png)

**Step 4: Create the Secure Configuration File (.env)**

To query VirusTotal safely, a private API key is required. To protect this key from exposure in your scripts, save it as an environment variable in a hidden .env file

Run this command:
```bash
```
**nano .env**
```
```
Inside the nano editor, paste your API key matching this format

**VT_API_KEY=YOUR_ACTUAL_API_KEY_HERE**

Save (Press Ctrl + O, the press Enter)

Exit (Press Ctrl + X) 

![Image](./Screenshots/4VT_API_KEY.png)


![Image](./Screenshots/2popup_tool.png)

![Image](./Screenshots/2popup_tool.png)

![Image](./Screenshots/2popup_tool.png)

![Image](./Screenshots/2popup_tool.png)

![Image](./Screenshots/2popup_tool.png)

![Image](./Screenshots/2popup_tool.png)

![Image](./Screenshots/2popup_tool.png)

![Image](./Screenshots/2popup_tool.png)
