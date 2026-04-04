#!/bin/bash

# Ensure running with sufficient privileges
if [ "$EUID" -ne 0 ]; then
    echo "[!] Please run this script as root (sudo) for full visibility."
fi

echo "========================================"
echo "    System & Network Diagnostic Tool    "
echo "========================================"

echo "[*] Checking for duplicate MAC addresses in ARP table (Potential MitM)..."
# Count occurrences of MAC addresses. Exclude incomplete entries.
DUPLICATES=$(arp -an | grep -v 'incomplete' | awk '{print $4}' | sort | uniq -d)
if [ -z "$DUPLICATES" ]; then
    echo "  -> No duplicate MAC addresses found in ARP cache."
else
    echo "  [!] WARNING: Duplicate MAC addresses found! Potential ARP Spoofing/MitM:"
    echo "$DUPLICATES"
fi

echo -e "\n[*] Checking /etc/hosts for potentially malicious entries..."
# Exclude comments and standard localhost entries
SUSPICIOUS_HOSTS=$(grep -vE '^#|^127\.0\.0\.1|^::1' /etc/hosts | awk '{print $1}')
if [ -z "$SUSPICIOUS_HOSTS" ]; then
    echo "  -> /etc/hosts looks clean."
else
    echo "  [!] WARNING: Non-standard entries found in /etc/hosts:"
    grep -vE '^#|^127\.0\.0\.1|^::1' /etc/hosts
fi

echo -e "\n[*] Checking active listening ports..."
# Using ss to show listening TCP/UDP ports and associated processes
ss -tulpn | grep LISTEN || echo "  -> No active listening ports or missing privileges."

echo -e "\n[*] Checking active Chrome/Chromium connections via ss..."
# Find PIDs for chrome/chromium and show their connections
CHROME_PIDS=$(pgrep -f "chrome|chromium" | tr '\n' '|' | sed 's/|$//')
if [ -n "$CHROME_PIDS" ]; then
    ss -tunp | grep -E "pid=($CHROME_PIDS)" || echo "  -> No established external connections found for Chrome/Chromium."
else
    echo "  -> Chrome/Chromium is not currently running."
fi

echo -e "\n[*] Checking for active Proxy Environment Variables..."
PROXY_VARS=$(env | grep -i 'proxy')
if [ -z "$PROXY_VARS" ]; then
    echo "  -> No active proxy environment variables found."
else
    echo "  [!] WARNING: Proxy variables configured:"
    echo "$PROXY_VARS"
fi

echo "========================================"
echo "          Diagnostic Complete           "
echo "========================================"
