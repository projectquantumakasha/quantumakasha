#!/bin/bash

echo "============================================="
echo "        Quick Network Diagnostics            "
echo "============================================="

echo -e "\n--- ARP Table (Local Network Devices) ---"
arp -a || ip neigh

echo -e "\n--- DNS Configuration ---"
cat /etc/resolv.conf | grep nameserver

echo -e "\n--- Hosts File (Potential Hijacking) ---"
cat /etc/hosts | grep -v "^#" | grep -v "^$" | grep -v "localhost" | grep -v "127.0.0.1" || echo "No custom entries found."

echo -e "\n--- Active Listening Ports ---"
ss -tulpn | grep LISTEN

echo -e "\n--- Chrome/Chromium Connections ---"
# Check both chrome and chromium
ss -tnp | grep -E 'chrome|chromium' || echo "No active Chrome/Chromium connections found."

echo -e "\n--- Suspicious Processes in /tmp or /dev/shm ---"
lsof +D /tmp +D /dev/shm 2>/dev/null | grep -E 'COMMAND|REG' || echo "None found."

echo -e "\n============================================="
echo "              Check Complete                 "
echo "============================================="
