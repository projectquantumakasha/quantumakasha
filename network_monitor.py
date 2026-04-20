import psutil
import socket

# Known telemetry domains to flag
TELEMETRY_DOMAINS = [
    'google-analytics.com',
    'telemetry.mozilla.org',
    'doubleclick.net',
    'googleadservices.com',
    'analytics',
    'telemetry',
    'tracking',
]

def get_chrome_connections():
    """Fetches active network connections for Chrome/Chromium processes."""
    connections = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            name = proc.info['name']
            if name and ('chrome' in name.lower() or 'chromium' in name.lower()):
                conns = proc.connections(kind='inet')
                for conn in conns:
                    if conn.status == 'ESTABLISHED':
                        connections.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'laddr': conn.laddr,
                            'raddr': conn.raddr,
                        })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return connections

def resolve_ip(ip):
    """Performs reverse DNS resolution for an IP address."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return "Unknown"

def is_telemetry(hostname):
    """Checks if a hostname matches known telemetry domains."""
    hostname_lower = hostname.lower()
    for domain in TELEMETRY_DOMAINS:
        if domain in hostname_lower:
            return True
    return False

def main():
    print("Monitoring active Chrome connections...")
    conns = get_chrome_connections()
    if not conns:
        print("No active Chrome connections found.")
    for c in conns:
        remote_ip = c['raddr'].ip
        remote_port = c['raddr'].port
        hostname = resolve_ip(remote_ip)

        telemetry_flag = "[TELEMETRY DETECTED]" if is_telemetry(hostname) else ""

        print(f"PID: {c['pid']} | Name: {c['name']} | Remote: {remote_ip}:{remote_port} | Host: {hostname} {telemetry_flag}")

if __name__ == '__main__':
    main()
