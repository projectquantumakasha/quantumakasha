# System & Network Monitoring Guide

This guide provides instructions on how to use the provided scripts and manual techniques to identify who is on your network, who is on your PC, and how to spot potential telemetry or phishing activity, especially on Linux and Google Chrome.

## 1. Quick Check (Bash Script)

The `quick_check.sh` script uses standard Linux commands to give you an immediate overview of your system's security posture.

**How to run:**
```bash
./quick_check.sh
```
*(Tip: Run with `sudo ./quick_check.sh` to see the Process IDs for all network connections).*

**What it checks:**
*   **Logged in Users (`who`):** Shows users currently logged into your machine via terminal or SSH.
*   **Active Connections (`ss`):** Shows what IP addresses your computer is currently talking to.
*   **ARP Table (`arp -a`):** Shows the devices on your local network that your computer has communicated with recently.
*   **Login History (`last`):** Shows a history of who has logged into your machine recently.

## 2. Advanced Monitoring (Python Script)

The `network_monitor.py` script provides a more structured view, focusing on active connections and potential Man-in-the-Middle (MitM) attacks.

**Prerequisites:**
```bash
pip install psutil
```

**How to run:**
```bash
python3 network_monitor.py
```
*(Tip: Run with `sudo python3 network_monitor.py` to ensure it has permissions to read all process names).*

**Key Features:**
*   **Process Mapping:** Attempts to map active network connections to the specific application (e.g., Chrome, SSH) making the connection.
*   **MitM Detection:** Checks the ARP table for duplicate MAC addresses. If two different IP addresses claim to have the same MAC address, it is a strong indicator of an ARP Spoofing attack (a common MitM technique where an attacker intercepts your traffic).

## 3. Chrome Specific Monitoring (Telemetry & Phishing)

Monitoring Chrome requires looking at both the network connections it makes and inspecting its internal developer tools.

### A. Checking System-Level Chrome Connections
The `network_monitor.py` script automatically filters for `chrome` or `chromium` processes to show you what remote servers your browser is talking to.

### B. Deep Inspection using Chrome DevTools
To see exactly what data Chrome (or a specific website) is sending:

1.  Open Chrome.
2.  Press `F12` (or `Ctrl+Shift+I`) to open Developer Tools.
3.  Go to the **Network** tab.
4.  Check the **Preserve log** checkbox (so data isn't lost when you navigate).
5.  Filter by **Fetch/XHR**. This shows background data requests, often used by telemetry scripts and trackers.
6.  Browse as normal or leave the tab open.
7.  **Analyze:** Look at the "Domain" column. Are there requests going to known tracking domains (e.g., `google-analytics.com`, `telemetry.mozilla.org`, or unrecognized domains)? Click on a request and check the "Payload" or "Request" tabs to see exactly what data is being sent.

### C. Checking for Malicious Extensions (Phishing/Data Theft)
Extensions have deep access to your browsing activity.

1.  Navigate to `chrome://extensions/` in your Chrome address bar.
2.  Review all installed extensions.
3.  Remove *anything* you do not recognize or do not actively use. Malicious extensions are a primary way attackers steal data or inject phishing overlays.
4.  Click "Details" on an extension to see what permissions it has. Be wary of extensions that have "Read and change all your data on all websites".

## 4. General Linux Security Tips
*   Keep your system updated: `sudo apt update && sudo apt upgrade`
*   Use a firewall (like `ufw`) to restrict incoming connections: `sudo ufw enable`
*   If you suspect compromise, check your `~/.ssh/authorized_keys` file to ensure no unknown attacker has added their key for persistent access.
