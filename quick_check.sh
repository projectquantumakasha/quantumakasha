#!/bin/bash

# Quick system diagnostic script for MitM and phishing detection
# Requires root privileges

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

echo "--- System Diagnostic Check ---"

echo "1. Checking ARP table for duplicate MAC addresses..."
# Strict regex for MAC address, checking for duplicates which might indicate MitM (ARP spoofing)
# Extract only lines with IP and MAC, sort by MAC, count duplicates
ARP_OUTPUT=$(arp -an)
DUPLICATES=$(echo "$ARP_OUTPUT" | grep -oE '([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})' | sort | uniq -d)

if [ -z "$DUPLICATES" ]; then
    echo "  [OK] No duplicate MAC addresses found in ARP table."
else
    echo "  [WARNING] Duplicate MAC addresses found! Possible ARP spoofing (MitM):"
    for MAC in $DUPLICATES; do
        echo "    MAC: $MAC is associated with multiple IPs:"
        echo "$ARP_OUTPUT" | grep -i "$MAC" | awk '{print "      "$2}'
    done
fi

echo "2. Checking System Proxy Variables..."
if [ -n "$http_proxy" ] || [ -n "$https_proxy" ] || [ -n "$HTTP_PROXY" ] || [ -n "$HTTPS_PROXY" ]; then
    echo "  [WARNING] System proxy variables are set. Ensure these are intentional."
    [ -n "$http_proxy" ] && echo "    http_proxy: $http_proxy"
    [ -n "$https_proxy" ] && echo "    https_proxy: $https_proxy"
    [ -n "$HTTP_PROXY" ] && echo "    HTTP_PROXY: $HTTP_PROXY"
    [ -n "$HTTPS_PROXY" ] && echo "    HTTPS_PROXY: $HTTPS_PROXY"
else
    echo "  [OK] No common system proxy variables set."
fi

echo "3. Auditing /etc/hosts for suspicious entries..."
# Check for entries that aren't localhost/loopback or ipv6 standard
SUSPICIOUS_HOSTS=$(grep -vE '^\s*#' /etc/hosts | grep -vE '^\s*127\.0\.0\.1' | grep -vE '^\s*::1' | grep -vE '^\s*ff0[0-9]:' | grep -vE '^\s*fe00:' | grep -vE '^\s*$')
if [ -z "$SUSPICIOUS_HOSTS" ]; then
    echo "  [OK] /etc/hosts looks clean."
else
    echo "  [INFO] Found non-standard entries in /etc/hosts. Verify if these are expected:"
    echo "$SUSPICIOUS_HOSTS" | while read -r line; do
        echo "    $line"
    done
fi

echo "4. Checking /etc/resolv.conf..."
NAMESERVERS=$(grep -i '^nameserver' /etc/resolv.conf | awk '{print $2}')
if [ -z "$NAMESERVERS" ]; then
    echo "  [WARNING] No nameservers found in /etc/resolv.conf!"
else
    echo "  [INFO] Configured Nameservers:"
    for ns in $NAMESERVERS; do
        echo "    $ns"
    done
fi

echo "--- Diagnostic Check Complete ---"
