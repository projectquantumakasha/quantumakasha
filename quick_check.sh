#!/bin/bash

# Quick Check Script for Linux Network Anomalies
# Checks for signs of MitM, unexpected listening ports, and anomalous browser behavior.

echo "=== Linux Quick Network & System Check ==="
echo "Running diagnostics..."

# Check if run as root (needed for some netstat/ss output and reading some files)
if [ "$EUID" -ne 0 ]; then
  echo "[!] Warning: Please run as root (sudo) for complete diagnostics."
fi

echo -e "\n[*] Checking ARP table for potential MitM (duplicate MAC addresses)..."
# Count occurrences of MAC addresses in the arp table. If any MAC appears more than once for different IPs, it could indicate ARP spoofing.
arp_output=$(arp -an)
if [ -z "$arp_output" ]; then
    echo "    ARP table is empty."
else
    duplicates=$(echo "$arp_output" | awk '{print $4}' | grep -v "incomplete" | sort | uniq -c | awk '$1 > 1')
    if [ -n "$duplicates" ]; then
        echo "    [!] WARNING: Duplicate MAC addresses found in ARP table! Possible ARP Spoofing/MitM:"
        echo "$duplicates"
    else
        echo "    No obvious duplicate MAC addresses in ARP table."
    fi
fi

echo -e "\n[*] Checking /etc/hosts for suspicious entries..."
# Check for non-standard entries (excluding localhost and comments)
suspicious_hosts=$(grep -v '^#' /etc/hosts | grep -v '127.0.0.1' | grep -v '::1' | grep -v 'localhost' | grep '[^[:space:]]')
if [ -n "$suspicious_hosts" ]; then
    echo "    [!] Potential unauthorized or manual modifications in /etc/hosts:"
    echo "$suspicious_hosts"
else
    echo "    /etc/hosts looks clean."
fi

echo -e "\n[*] Checking currently listening network ports..."
if command -v ss &> /dev/null; then
    ss -tulnp | grep -v "127.0.0.1" | grep -v "::1" | head -n 10
else
    netstat -tulnp | grep -v "127.0.0.1" | grep -v "::1" | head -n 10
fi
echo "    (Showing top 10 external listening ports)"

echo -e "\n[*] Checking Chrome/Chromium processes for unusual flags (telemetry, remote debugging)..."
chrome_procs=$(ps aux | grep -iE 'chrome|chromium' | grep -v grep)
if [ -z "$chrome_procs" ]; then
    echo "    No Chrome/Chromium processes found running."
else
    echo "    Chrome/Chromium is running. Checking flags..."
    if echo "$chrome_procs" | grep -qiE -- '--remote-debugging-port|--disable-web-security|--ignore-certificate-errors'; then
         echo "    [!] WARNING: Dangerous or suspicious flags detected in running Chrome instances:"
         echo "$chrome_procs" | grep -iE -- '--remote-debugging-port|--disable-web-security|--ignore-certificate-errors' | awk '{print $11, $12, $13}' | head -n 3
    else
         echo "    No obviously dangerous debugging or security-bypassing flags detected."
    fi
fi

echo -e "\n=== Check Complete ==="
echo "Note: This is a basic heuristic check. Thorough analysis requires deep packet inspection (e.g., Wireshark)."
