#!/usr/bin/env python3
import os
import sys
import psutil
import socket
import functools

# Known telemetry or tracking domains
TELEMETRY_DOMAINS = [
    "1e100.net", # Google
    "telemetry",
    "analytics",
    "tracking",
    "metrics",
    "logs",
]

@functools.lru_cache(maxsize=1024)
def get_host_by_addr(ip):
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except socket.herror:
        return "Unknown"
    except Exception:
        return "Error"

def check_privileges():
    if os.geteuid() != 0:
        print("Warning: This script should be run with root privileges for full visibility (sudo).")
        # Do not exit immediately to allow testing, or we can just warn.

def is_telemetry(host):
    host_lower = host.lower()
    for domain in TELEMETRY_DOMAINS:
        if domain in host_lower:
            return True
    return False

def monitor_connections():
    print(f"{'PID':<10} | {'Process Name':<20} | {'Local Address':<25} | {'Remote Address':<25} | {'Remote Host':<30} | {'Status':<15} | {'Flags'}")
    print("-" * 140)

    try:
        connections = psutil.net_connections(kind='inet')
    except psutil.AccessDenied:
        print("Access denied to some connections. Run with sudo.")
        connections = []

    for conn in connections:
        if conn.status == 'ESTABLISHED':
            try:
                proc = psutil.Process(conn.pid) if conn.pid else None
                proc_name = proc.name() if proc else "Unknown"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                proc_name = "Unknown"

            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""

            remote_ip = conn.raddr.ip if conn.raddr else None
            remote_host = ""
            flags = []

            if remote_ip:
                remote_host = get_host_by_addr(remote_ip)
                if is_telemetry(remote_host):
                    flags.append("TELEMETRY")

            # Highlight browsers specifically
            if proc_name.lower() in ['chrome', 'chromium', 'firefox', 'brave', 'edge', 'opera']:
                flags.append("BROWSER")

            flag_str = ", ".join(flags)

            print(f"{str(conn.pid):<10} | {proc_name:<20} | {laddr:<25} | {raddr:<25} | {remote_host:<30} | {conn.status:<15} | {flag_str}")

def main():
    check_privileges()
    monitor_connections()

if __name__ == "__main__":
    main()
