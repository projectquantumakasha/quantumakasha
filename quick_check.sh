#!/bin/bash

# Diagnostic script to check for signs of MitM, phishing, and proxy hijacking

echo "Running Quick Network Diagnostic Checks..."
echo "----------------------------------------"

# 1. ARP Table Check for duplicates (MitM indicator)
echo "[*] Checking ARP table for duplicate MAC addresses..."
# We use command substitution to avoid insecure temp files
arp_output=$(arp -an)

# Extract MAC addresses using strict regex and check for duplicates
duplicates=$(echo "$arp_output" | grep -oE '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' | sort | uniq -d)

if [ -n "$duplicates" ]; then
    echo "[!] WARNING: Duplicate MAC addresses found in ARP table! Potential ARP Spoofing/MitM detected."
    echo "Duplicates:"
    echo "$duplicates"
else
    echo "[+] ARP table looks clean. No duplicate MAC addresses found."
fi

echo "----------------------------------------"

# 2. System Proxy Check
echo "[*] Checking for system-wide proxy variables..."
proxies=$(env | grep -iE 'http_proxy|https_proxy|ftp_proxy|all_proxy')

if [ -n "$proxies" ]; then
    echo "[!] WARNING: System proxy variables are set. This could be intercepting traffic."
    echo "$proxies"
else
    echo "[+] No system proxy variables detected."
fi

echo "----------------------------------------"

# 3. Check /etc/hosts for suspicious entries
echo "[*] Checking /etc/hosts for suspicious non-local entries..."
# Exclude lines starting with #, 127., ::1, 255., ff, fe
suspicious_hosts=$(grep -v '^#' /etc/hosts | grep -v '^\s*$' | grep -vE '^\s*(127\.|::1|255\.|ff|fe)')

if [ -n "$suspicious_hosts" ]; then
    echo "[!] WARNING: Suspicious entries found in /etc/hosts. Could be phishing/redirection."
    echo "$suspicious_hosts"
else
    echo "[+] /etc/hosts looks clean."
fi

echo "----------------------------------------"

# 4. Check /etc/resolv.conf for DNS nameservers
echo "[*] Checking /etc/resolv.conf for nameservers..."
nameservers=$(grep '^nameserver' /etc/resolv.conf)

if [ -n "$nameservers" ]; then
    echo "[i] Configured nameservers:"
    echo "$nameservers"
else
    echo "[!] WARNING: No nameservers found in /etc/resolv.conf."
fi

echo "----------------------------------------"
echo "Checks completed."
