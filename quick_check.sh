#!/bin/bash

# Quick Check Script for Identifying MitM and suspicious system settings

echo "=========================================="
echo "    Quick System Diagnostics Check"
echo "=========================================="

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
  echo "[!] Warning: Run this script with sudo for full network and system visibility."
fi

echo -e "\n[+] Checking for ARP Spoofing (Duplicate MAC Addresses in ARP table)..."
# Extract ARP table, ignoring header. Ensure valid MAC formatting
# If arp command is missing, try ip neigh
if command -v arp >/dev/null 2>&1; then
    arp_output=$(arp -an | grep -oE '([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})')
else
    arp_output=$(ip neigh show | grep -oE '([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})')
fi

duplicate_macs=$(echo "$arp_output" | sort | uniq -d)

if [ -z "$duplicate_macs" ]; then
    echo "  -> No duplicate MAC addresses found in ARP table. (Good)"
else
    echo "  -> [WARNING] Duplicate MAC addresses detected! Possible ARP Spoofing/MitM:"
    echo "$duplicate_macs"
fi

echo -e "\n[+] Checking System Proxy Variables..."
proxy_vars=$(env | grep -iE 'http_proxy|https_proxy|ftp_proxy|all_proxy')

if [ -z "$proxy_vars" ]; then
    echo "  -> No system proxy environment variables set. (Good)"
else
    echo "  -> [WARNING] Proxy variables are set. Verify if these are expected:"
    echo "$proxy_vars"
fi

echo -e "\n[+] Checking /etc/hosts for suspicious entries..."
# Exclude lines that are comments or just localhost/ip6
hosts_entries=$(grep -vE '^#|^127\.0\.0\.1|^::1' /etc/hosts | awk '{print $1, $2}')
if [ -z "$hosts_entries" ]; then
    echo "  -> No unusual entries found in /etc/hosts. (Good)"
else
    echo "  -> [INFO] Checking /etc/hosts entries (Please review for anomalies):"
    echo "$hosts_entries"
fi

echo -e "\n[+] Checking /etc/resolv.conf for configured DNS servers..."
dns_servers=$(grep -i '^nameserver' /etc/resolv.conf)
if [ -z "$dns_servers" ]; then
    echo "  -> [WARNING] No nameserver found in /etc/resolv.conf. Network issues possible."
else
    echo "  -> Current DNS servers:"
    echo "$dns_servers"
fi

echo -e "\n=========================================="
echo "    Diagnostics Check Complete"
echo "=========================================="
