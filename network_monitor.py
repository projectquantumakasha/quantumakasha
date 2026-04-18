import os
import sys
import psutil
import socket

def check_root():
    if os.geteuid() != 0:
        print("Error: This script must be run with root privileges.")
        print("Please run with: sudo python3 network_monitor.py")
        sys.exit(1)

def resolve_ip(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"
    except Exception:
        return "Unknown"

def is_telemetry(domain):
    suspicious = ['telemetry', 'metrics', 'analytics', 'track', 'google', 'log', 'report']
    domain_lower = domain.lower()
    for word in suspicious:
        if word in domain_lower:
            return True
    return False

def main():
    check_root()

    print(f"{'PID':<8} {'Process':<20} {'Local Address':<25} {'Remote Address':<25} {'Hostname':<40} {'Flags'}")
    print("-" * 140)

    try:
        connections = psutil.net_connections(kind='inet')
    except psutil.AccessDenied:
        print("Access denied to network connections. Ensure you are running as root.")
        sys.exit(1)

    for conn in connections:
        if conn.status != 'ESTABLISHED':
            continue

        if not conn.raddr:
            continue

        pid = conn.pid
        proc_name = "Unknown"
        if pid:
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
        raddr = f"{conn.raddr.ip}:{conn.raddr.port}"

        hostname = resolve_ip(conn.raddr.ip)

        flags = []
        if is_telemetry(hostname) or is_telemetry(proc_name):
            flags.append("TELEMETRY")

        if "chrome" in proc_name.lower() or "chromium" in proc_name.lower():
            flags.append("BROWSER")

        flag_str = ", ".join(flags)

        print(f"{pid if pid else '-':<8} {proc_name:<20} {laddr:<25} {raddr:<25} {hostname:<40} {flag_str}")

if __name__ == "__main__":
    main()
