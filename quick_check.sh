#!/bin/bash

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Error: This script must be run with root privileges."
  echo "Please run with: sudo ./quick_check.sh"
  exit 1
fi

echo "=========================================="
echo "    System Diagnostic Quick Check         "
echo "=========================================="
echo ""

# Check ARP tables for duplicate MAC addresses
echo "[*] Checking ARP tables for potential MitM/ARP Spoofing..."

# Get ARP entries, ignore incomplete ones
arp_entries=$(arp -a | grep -v 'incomplete')

if [ -z "$arp_entries" ]; then
    echo "No complete ARP entries found."
else
    # Extract MAC addresses using strict regex and find duplicates
    duplicates=$(echo "$arp_entries" | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}' | sort | uniq -d)

    if [ -n "$duplicates" ]; then
        echo "WARNING: Duplicate MAC addresses found in ARP table!"
        echo "This could indicate an ARP spoofing or Man-in-the-Middle (MitM) attack."
        echo "Duplicate MACs:"
        echo "$duplicates"
        echo "Full ARP entries for reference:"
        for mac in $duplicates; do
            echo "$arp_entries" | grep -i "$mac"
        done
    else
        echo "No duplicate MAC addresses detected in ARP table."
    fi
fi
echo ""

# Inspect system proxy variables
echo "[*] Checking system proxy variables..."
proxies=$(env | grep -i 'proxy')
if [ -n "$proxies" ]; then
    echo "WARNING: Proxy variables are set. Ensure these are intentional:"
    echo "$proxies"
else
    echo "No system proxy variables detected."
fi
echo ""

# Check /etc/hosts for suspicious entries
echo "[*] Checking /etc/hosts for non-standard entries..."
hosts_entries=$(grep -v '^#' /etc/hosts | grep -v '^$' | grep -v 'localhost' | grep -v '127.0.0.1' | grep -v '::1')
if [ -n "$hosts_entries" ]; then
    echo "Non-standard entries found in /etc/hosts:"
    echo "$hosts_entries"
    echo "Please verify if these are intentional."
else
    echo "No suspicious non-standard entries found in /etc/hosts."
fi
echo ""

# Output DNS configurations from /etc/resolv.conf
echo "[*] Outputting DNS configuration from /etc/resolv.conf..."
nameservers=$(grep '^nameserver' /etc/resolv.conf)
if [ -n "$nameservers" ]; then
    echo "Configured nameservers:"
    echo "$nameservers"
else
    echo "No nameservers found in /etc/resolv.conf."
fi
echo ""

echo "=========================================="
echo "    Quick Check Complete                  "
echo "=========================================="
