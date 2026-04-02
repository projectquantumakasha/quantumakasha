#!/bin/bash

echo "======================================"
echo "  Quick System & Network Diagnostics  "
echo "======================================"

echo -e "\n[+] Logged in Users (Who is on my PC?)"
who

echo -e "\n[+] Active Network Connections (ss -tunap | grep ESTAB)"
# Requires sudo for full process info, but we run what we can
ss -tunap | grep ESTAB

echo -e "\n[+] Listening Ports (ss -tuln)"
ss -tuln

echo -e "\n[+] ARP Table (Who is in my local network?)"
arp -a

echo -e "\n[+] Recent Login History (last -n 5)"
last -n 5

echo -e "\n[+] Chrome specific processes"
pgrep -af chrome || echo "No Chrome processes running."

echo -e "\n======================================"
echo "  Diagnostics Complete                "
echo "======================================"
