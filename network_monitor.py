import psutil
import socket
import os

# Known telemetry/tracking domains or keywords for basic flagging
KNOWN_TELEMETRY = [
    'google-analytics.com', 'doubleclick.net', 'telemetry', 'metrics',
    'tracking', 'analytics', 'log.optimizely.com', 'browser.pipe.aria.microsoft.com',
    'events.data.microsoft.com', 'watson.telemetry.microsoft.com', 'app-measurement.com'
]

def check_is_telemetry(hostname):
    hostname_lower = hostname.lower()
    for keyword in KNOWN_TELEMETRY:
        if keyword in hostname_lower:
            return True
    return False

def get_process_name(pid):
    try:
        process = psutil.Process(pid)
        return process.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "Unknown"

def main():
    if os.geteuid() != 0:
        print("This script must be run as root to see all network connections.")
        return

    print("--- Active Network Connections & Telemetry Check ---")

    connections = psutil.net_connections(kind='inet')

    found_telemetry = False

    for conn in connections:
        # Only care about established connections
        if conn.status != 'ESTABLISHED':
            continue

        raddr = conn.raddr
        if not raddr:
            continue

        remote_ip = raddr.ip
        remote_port = raddr.port

        # Skip local connections
        if remote_ip in ['127.0.0.1', '::1', '0.0.0.0']:
            continue

        process_name = get_process_name(conn.pid)

        # Optional: Filter for browser-related processes if needed, but showing all is better for full scope
        # if 'chrome' not in process_name.lower() and 'firefox' not in process_name.lower():
        #     continue

        try:
            # Perform reverse DNS resolution
            hostname, _, _ = socket.gethostbyaddr(remote_ip)
        except socket.herror:
            hostname = remote_ip

        is_telemetry = check_is_telemetry(hostname)

        flag = "[TELEMETRY/TRACKING]" if is_telemetry else "[OK]"
        if is_telemetry:
            found_telemetry = True

        print(f"{flag} PID: {conn.pid} | Process: {process_name} | Remote: {remote_ip}:{remote_port} | Host: {hostname}")

    if not found_telemetry:
        print("\nNo known telemetry/tracking connections detected.")

if __name__ == "__main__":
    main()
