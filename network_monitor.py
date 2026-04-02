import psutil
import socket
import subprocess
import re

def get_active_connections():
    print("=== Active Network Connections ===")
    print(f"{'Protocol':<10} {'Local Address':<25} {'Remote Address':<25} {'Status':<15} {'PID':<10} {'Process Name'}")
    print("-" * 100)

    connections = psutil.net_connections(kind='inet')
    for conn in connections:
        if conn.status == 'ESTABLISHED':
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"

            # Try to get process name
            proc_name = "N/A"
            if conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    proc_name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = "Access Denied"

            proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            print(f"{proto:<10} {laddr:<25} {raddr:<25} {conn.status:<15} {str(conn.pid):<10} {proc_name}")

def check_arp_table():
    print("\n=== ARP Table (Potential MitM Check) ===")
    print("Checking for duplicate MAC addresses which could indicate ARP Spoofing (MitM)...")
    try:
        # Run arp -a to get the ARP table
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
        lines = result.stdout.splitlines()

        mac_addresses = {}
        duplicates_found = False

        for line in lines:
            # Simple regex to extract IP and MAC
            match = re.search(r'\((.*?)\) at (([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))', line)
            if match:
                ip = match.group(1)
                mac = match.group(2)

                if mac in mac_addresses:
                    print(f"[!] WARNING: Duplicate MAC address found!")
                    print(f"    MAC: {mac} is claimed by both {mac_addresses[mac]} and {ip}")
                    print(f"    This is a strong indicator of an ARP Spoofing (Man-in-the-Middle) attack.")
                    duplicates_found = True
                else:
                    mac_addresses[mac] = ip

        if not duplicates_found:
            print("No duplicate MAC addresses found. ARP table looks normal.")

    except FileNotFoundError:
        print("The 'arp' command was not found. Please ensure net-tools is installed.")

def analyze_chrome_telemetry():
    print("\n=== Chrome Activity Check ===")
    print("To deeply analyze Chrome telemetry/phishing:")
    print("1. Open Chrome and press F12 (Developer Tools).")
    print("2. Go to the 'Network' tab.")
    print("3. Filter by 'Fetch/XHR' to see background data being sent.")
    print("4. Look for requests to known telemetry domains (e.g., google-analytics.com, telemetry.mozilla.org).")
    print("\nCurrently active Chrome connections on this system:")

    connections = psutil.net_connections(kind='inet')
    chrome_found = False
    for conn in connections:
        if conn.status == 'ESTABLISHED' and conn.pid:
            try:
                proc = psutil.Process(conn.pid)
                if 'chrome' in proc.name().lower() or 'chromium' in proc.name().lower():
                    raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                    print(f"  Chrome -> Connected to {raddr}")
                    chrome_found = True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    if not chrome_found:
        print("  No active Chrome connections found (or run with sudo to see all processes).")

if __name__ == "__main__":
    print("Starting System & Network Monitor...\n")
    get_active_connections()
    check_arp_table()
    analyze_chrome_telemetry()
    print("\nDone.")
