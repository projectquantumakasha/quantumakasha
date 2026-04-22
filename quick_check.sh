#!/bin/bash

# Diagnostic script for Linux system security checks
# This script must be run with root privileges to access all necessary information.

if [ "$EUID" -ne 0 ]; then
  echo "Please run this script with root privileges (sudo)."
  exit 1
fi

echo "============================================================"
echo "    System Security Quick Check (MitM, Proxies, DNS)      "
echo "============================================================"

# 1. ARP Table Check for MitM (ARP Spoofing)
echo "[*] Checking ARP table for duplicate MAC addresses..."
arp_output=$(arp -a)

# Extract MAC addresses using strict regex and check for duplicates
duplicates=$(echo "$arp_output" | grep -oE "([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}" | sort | uniq -d)

if [ -n "$duplicates" ]; then
    echo "[!] WARNING: Duplicate MAC addresses found in ARP table. Potential MitM (ARP Spoofing) detected:"
    echo "$duplicates"
else
    echo "[+] No duplicate MAC addresses found in ARP table."
fi

# 2. Proxy Variable Check
echo -e "\n[*] Checking system proxy variables..."
proxy_vars=("http_proxy" "https_proxy" "ftp_proxy" "all_proxy" "HTTP_PROXY" "HTTPS_PROXY" "FTP_PROXY" "ALL_PROXY")
proxy_found=0

for var in "${proxy_vars[@]}"; do
    # Using indirect parameter expansion to check environment variables
    # This checks variables available to root, which might differ from user.
    # We can also check /etc/environment
    val=$(printenv "$var")
    if [ -n "$val" ]; then
        echo "[!] WARNING: Proxy variable $var is set to: $val"
        proxy_found=1
    fi
done

# Check global /etc/environment
etc_proxies=$(grep -i "_proxy=" /etc/environment 2>/dev/null)
if [ -n "$etc_proxies" ]; then
    echo "[!] WARNING: Global proxies found in /etc/environment:"
    echo "$etc_proxies"
    proxy_found=1
fi

if [ $proxy_found -eq 0 ]; then
    echo "[+] No system proxy variables detected."
fi

# 3. DNS Configuration Check (/etc/resolv.conf)
echo -e "\n[*] Checking DNS configuration (/etc/resolv.conf)..."
dns_servers=$(grep "^nameserver" /etc/resolv.conf | awk '{print $2}')

if [ -n "$dns_servers" ]; then
    echo "Current DNS Servers:"
    echo "$dns_servers"
    echo "(Verify these are expected for your network to rule out malicious DNS routing/phishing)"
else
    echo "[!] WARNING: No DNS servers found in /etc/resolv.conf"
fi

# 4. Host File Check (/etc/hosts)
echo -e "\n[*] Checking /etc/hosts for unexpected entries..."
# We ignore standard localhost, broadcasthost, etc.
suspicious_hosts=$(grep -vE "^#|^127\.0\.0\.1|^::1|^255\.255\.255\.255|^ff0[0-2]::" /etc/hosts | grep -v "^$")

if [ -n "$suspicious_hosts" ]; then
    echo "[!] WARNING: Non-standard entries found in /etc/hosts:"
    echo "$suspicious_hosts"
else
    echo "[+] /etc/hosts looks clean."
fi

echo -e "\n============================================================"
echo "    Quick Check Complete. Please review any WARNINGs.       "
echo "============================================================"
