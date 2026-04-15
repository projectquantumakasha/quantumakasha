#!/usr/bin/env python3
import psutil
import socket
import os

def get_process_name(pid):
    try:
        process = psutil.Process(pid)
        return process.name(), process.cmdline()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "Unknown", []

def resolve_ip(ip):
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except socket.herror:
        return ip
    except Exception:
        return ip

def main():
    print("=== Active Network Monitor ===")
    print("Identifying active network connections and associated processes...\n")

    # Needs root for some processes
    if os.geteuid() != 0:
        print("[!] Warning: Run as root (sudo) to see all process information.\n")

    try:
        connections = psutil.net_connections(kind='inet')
    except psutil.AccessDenied:
        print("Access denied to network connections. Try running with sudo.")
        return

    suspicious_ports = {
        4444: "Metasploit default",
        1337: "Leet backdoor",
        31337: "BackOrifice",
        6667: "IRC (Botnets)",
        # Add more as needed
    }

    telemetry_domains = ["telemetry", "analytics", "1e100.net", "tracking", "metrics"]

    established_conns = [c for c in connections if c.status == 'ESTABLISHED']

    if not established_conns:
        print("No established network connections found.")
        return

    for conn in established_conns:
        laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
        raddr_ip = conn.raddr.ip if conn.raddr else "N/A"
        raddr_port = conn.raddr.port if conn.raddr else "N/A"
        raddr = f"{raddr_ip}:{raddr_port}"

        remote_host = resolve_ip(raddr_ip) if raddr_ip != "N/A" else "N/A"
        raddr_display = f"{remote_host}:{raddr_port}" if remote_host != raddr_ip else raddr

        pid = conn.pid
        pname, cmdline = get_process_name(pid) if pid else ("Unknown", [])

        print(f"[{pname}] (PID: {pid})")
        print(f"    Local: {laddr}  ->  Remote: {raddr_display} (IP: {raddr_ip})")

        # Telemetry check
        is_telemetry = remote_host != "N/A" and any(domain in remote_host.lower() for domain in telemetry_domains)

        # Chrome/Chromium check
        if "chrome" in pname.lower() or "chromium" in pname.lower():
            if is_telemetry:
                 print(f"    [!] Browser Telemetry/Tracking detected: Connection to {remote_host}")
            else:
                 print(f"    [*] Browser activity (Chrome/Chromium). Connected to {remote_host}.")
        elif is_telemetry:
             print(f"    [!] Non-Browser Telemetry/Tracking detected: Connection to {remote_host}")

        # Suspicious port check
        if raddr_port in suspicious_ports:
            print(f"    [!] WARNING: Connection to suspicious port {raddr_port} ({suspicious_ports[raddr_port]}).")

        # Check for unencrypted traffic (HTTP/Telnet/FTP) on unusual processes
        if raddr_port in [80, 23, 21] and "chrome" not in pname.lower() and "firefox" not in pname.lower():
            print(f"    [!] NOTE: Unencrypted traffic port ({raddr_port}) used by non-browser process.")

        print("-" * 50)

if __name__ == "__main__":
    if os.name != 'posix':
        print("This script is optimized for Linux/POSIX systems. Some features may not work as expected.")
    main()
