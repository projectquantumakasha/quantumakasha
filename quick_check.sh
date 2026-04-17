#!/bin/bash

echo "================================================="
echo " Quick System Diagnostic for MitM & Phishing Risks"
echo "================================================="
echo ""

echo "[1] Checking ARP Table for duplicate MAC addresses (Potential ARP Spoofing)..."
if command -v arp >/dev/null 2>&1; then
    dup_macs=$(arp -a | awk '{print $4}' | grep -iE '^([0-9a-f]{2}:){5}[0-9a-f]{2}$' | sort | uniq -d)
    if [ -n "$dup_macs" ]; then
        echo "WARNING: Duplicate MAC addresses found in ARP table!"
        echo "$dup_macs"
    else
        echo "OK: No duplicate MAC addresses detected."
    fi
elif command -v ip >/dev/null 2>&1; then
    dup_macs=$(ip neigh | awk '{print $5}' | grep -iE '^([0-9a-f]{2}:){5}[0-9a-f]{2}$' | sort | uniq -d)
    if [ -n "$dup_macs" ]; then
        echo "WARNING: Duplicate MAC addresses found in ARP table!"
        echo "$dup_macs"
    else
        echo "OK: No duplicate MAC addresses detected."
    fi
else
    echo "SKIPPED: 'arp' or 'ip' command not found."
fi
echo ""

echo "[2] Checking System Proxy Environment Variables..."
proxy_found=0
for var in http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY; do
    if [ -n "${!var}" ]; then
        echo "WARNING: Proxy variable $var is set to: ${!var}"
        proxy_found=1
    fi
done
if [ $proxy_found -eq 0 ]; then
    echo "OK: No active system proxy variables detected."
fi
echo ""

echo "[3] Checking /etc/hosts for suspicious entries..."
if [ -f /etc/hosts ]; then
    suspicious_entries=$(grep -Ev "^127\.0\.0\.1|^::1|^#|^$" /etc/hosts | grep -iE "google|login|bank|paypal|facebook|apple|microsoft|amazon")
    if [ -n "$suspicious_entries" ]; then
        echo "WARNING: Suspicious entries found in /etc/hosts redirecting known domains:"
        echo "$suspicious_entries"
    else
        echo "OK: No obvious suspicious redirects in /etc/hosts."
    fi
else
    echo "SKIPPED: /etc/hosts not found."
fi
echo ""

echo "[4] Displaying configured DNS Servers from /etc/resolv.conf..."
if [ -f /etc/resolv.conf ]; then
    grep "^nameserver" /etc/resolv.conf
else
    echo "SKIPPED: /etc/resolv.conf not found."
fi
echo ""

echo "================================================="
echo " Diagnostic Complete."
echo " Note: Run this script with sudo for best results."
echo "================================================="
