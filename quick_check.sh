#!/bin/bash

echo "========================================"
echo "    System Diagnostic Quick Check       "
echo "========================================"

echo ""
echo "[*] Checking for Proxy Environment Variables (Potential MitM)..."
if [ -n "$http_proxy" ] || [ -n "$https_proxy" ] || [ -n "$HTTP_PROXY" ] || [ -n "$HTTPS_PROXY" ]; then
    echo "    WARNING: Proxy variables are set!"
    echo "    http_proxy: $http_proxy"
    echo "    https_proxy: $https_proxy"
    echo "    HTTP_PROXY: $HTTP_PROXY"
    echo "    HTTPS_PROXY: $HTTPS_PROXY"
else
    echo "    No proxy variables found."
fi

echo ""
echo "[*] Checking ARP Table for duplicate MAC addresses (Potential ARP Spoofing)..."
arp_output=$(arp -a)
duplicates=$(echo "$arp_output" | awk '{print $4}' | grep -v "incomplete" | sort | uniq -d)
if [ -n "$duplicates" ]; then
    echo "    WARNING: Duplicate MAC addresses found in ARP table!"
    echo "$arp_output" | grep -f <(echo "$duplicates")
else
    echo "    No duplicate MAC addresses found."
    echo "    Current ARP Table:"
    arp -a | awk '{print "      " $0}'
fi

echo ""
echo "[*] Inspecting DNS Configuration (/etc/resolv.conf)..."
cat /etc/resolv.conf | grep nameserver | awk '{print "    " $0}'

echo ""
echo "[*] Inspecting Hosts File (/etc/hosts) for non-standard entries..."
cat /etc/hosts | grep -v "^127\.0\.0\.1" | grep -v "^::1" | grep -v "^#" | grep -v "^$" | awk '{print "    " $0}'
if [ $(cat /etc/hosts | grep -v "^127\.0\.0\.1" | grep -v "^::1" | grep -v "^#" | grep -v "^$" | wc -l) -eq 0 ]; then
    echo "    No non-standard entries found."
fi

echo ""
echo "[*] Listing Established Active Connections..."
ss -tunp | grep ESTAB | awk '{print "    " $0}'

echo ""
echo "========================================"
echo "          Diagnostics Complete          "
echo "========================================"
