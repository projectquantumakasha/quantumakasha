import socket
import functools
import psutil

# Cache DNS lookups to avoid blocking network calls and improve execution speed
@functools.lru_cache(maxsize=1024)
def get_hostname(ip_address):
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        return ip_address
    except Exception as e:
        return str(e)

# Known telemetry domains to flag
TELEMETRY_DOMAINS = [
    "google-analytics.com",
    "telemetry",
    "metrics",
    "tracking",
    "log",
    "analytics"
]

def is_telemetry(hostname):
    hostname_lower = hostname.lower()
    for domain in TELEMETRY_DOMAINS:
        if domain in hostname_lower:
            return True
    return False

def monitor_connections():
    print("Active Network Connections Mapping (Linux / Chrome / Chromium):")
    print("-" * 80)
    print(f"{'PID':<8} {'Process':<15} {'Local Address':<25} {'Remote Address':<25} {'Status':<15} {'Telemetry/Flag'}")
    print("-" * 80)

    try:
        connections = psutil.net_connections(kind='inet')
    except psutil.AccessDenied:
        print("Access denied: Please run this script with root privileges (sudo).")
        return

    for conn in connections:
        if not conn.raddr: # Only check established connections with remote address
            continue

        pid = conn.pid
        if not pid:
            continue

        try:
            process = psutil.Process(pid)
            process_name = process.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            process_name = "Unknown"

        # Focus on Chrome/Chromium and system/Linux activity loosely, or all if we want comprehensive
        # User specified "especially on linux and chrome"

        local_ip, local_port = conn.laddr
        remote_ip, remote_port = conn.raddr

        local_addr_str = f"{local_ip}:{local_port}"
        remote_addr_str = f"{remote_ip}:{remote_port}"

        hostname = get_hostname(remote_ip)

        is_tel = is_telemetry(hostname)
        flag = "TELEMETRY DETECTED" if is_tel else ""

        if is_tel:
             remote_addr_str = f"{hostname} ({remote_ip}:{remote_port})"
        else:
             if hostname != remote_ip:
                 remote_addr_str = f"{hostname} ({remote_ip}:{remote_port})"

        # We display the output
        print(f"{pid:<8} {process_name:<15} {local_addr_str:<25} {remote_addr_str:<25} {conn.status:<15} {flag}")

if __name__ == "__main__":
    monitor_connections()
