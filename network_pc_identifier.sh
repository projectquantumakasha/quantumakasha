#!/bin/bash

# Network and PC Identifier Script (Linux)
# This script uses standard Linux tools to gather information about active connections,
# potential local network Man-in-the-Middle (MitM) indicators, and system processes.

echo "=========================================================="
echo "      LINUX NETWORK & PC SECURITY IDENTIFIER"
echo "=========================================================="
echo "Note: Some commands might require root (sudo) privileges"
echo "to display full process information."
echo ""

# 1. Active Network Connections
echo "--- [1] Active Network Connections (Who is connected to you / Who you are connected to) ---"
echo "Showing established connections and the processes making them:"
# ss (socket statistics) is a modern replacement for netstat
ss -tupan | grep -E "(ESTAB|State)" | head -n 20
echo "... (showing top 20 established connections)"
echo ""

# 2. Listening Ports (Potential backdoors or unauthorized services)
echo "--- [2] Listening Ports (Open doors on your PC) ---"
ss -tulpn | grep LISTEN | head -n 20
echo ""

# 3. ARP Table Check (Detecting local MitM / ARP Spoofing)
echo "--- [3] ARP Table (Local Network Neighbors) ---"
echo "Checking the ARP cache. If you see two different IP addresses (especially your router) "
echo "sharing the SAME MAC address, you may be a victim of an ARP spoofing MitM attack."
arp -a
echo ""

# 4. Chrome Extensions (Linux)
echo "--- [4] Installed Chrome Extensions ---"
echo "Malicious extensions can act as spyware, perform MitM on your browser traffic, or inject phishing pages."
CHROME_EXT_DIR="$HOME/.config/google-chrome/Default/Extensions"
if [ -d "$CHROME_EXT_DIR" ]; then
    echo "Found extensions in: $CHROME_EXT_DIR"
    ls -1 "$CHROME_EXT_DIR"
    echo "(Tip: Copy these 32-character IDs and paste them into the Chrome Web Store URL to identify them: https://chrome.google.com/webstore/detail/<ID>)"
else
    echo "Default Chrome extension directory not found. You might be using Chromium, Brave, or a custom profile."
fi
echo ""

# 5. Suspicious Login Attempts (Basic local telemetry)
echo "--- [5] Recent Failed Login Attempts ---"
if [ -r /var/log/auth.log ]; then
    tail -n 20 /var/log/auth.log | grep -iE "failed|invalid|session opened for user root"
elif [ -r /var/log/secure ]; then
    # For RHEL/CentOS/Fedora systems
    tail -n 20 /var/log/secure | grep -iE "failed|invalid|session opened for user root"
else
    echo "Auth logs not readable. Run with sudo to see failed SSH or local login attempts."
fi
echo ""
echo "=========================================================="
echo "Done."
