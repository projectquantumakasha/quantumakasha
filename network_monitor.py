import psutil
import socket
import logging
from collections import defaultdict

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_process_name(pid):
    """Retrieve the name of the process given its PID."""
    try:
        process = psutil.Process(pid)
        return process.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "Unknown"

def is_chrome_process(name):
    """Check if the process name corresponds to Chrome or Chromium."""
    name_lower = name.lower()
    return 'chrome' in name_lower or 'chromium' in name_lower

def check_suspicious_ports(port):
    """Check if the port is known to be used by malware or backdoors."""
    suspicious_ports = {
        # Common malware/backdoor ports
        31337: "Back Orifice / Elite",
        6667: "IRC / Botnets",
        1337: "WaStE",
        27374: "Sub7",
        12345: "NetBus",
        12346: "NetBus",
        1080: "Socks Proxy (Potential abuse)",
        3128: "Squid Proxy (Potential abuse)"
    }
    return suspicious_ports.get(port, None)

def analyze_connections():
    """Analyze all active network connections."""
    logging.info("Starting network analysis...")

    connections = psutil.net_connections(kind='inet')
    chrome_connections = []
    suspicious_connections = []
    process_connections = defaultdict(list)

    for conn in connections:
        if conn.status == 'ESTABLISHED' or conn.status == 'LISTEN':
            if conn.pid is None:
                continue

            proc_name = get_process_name(conn.pid)
            local_ip, local_port = conn.laddr if conn.laddr else ("", "")
            remote_ip, remote_port = conn.raddr if conn.raddr else ("", "")

            conn_details = {
                'pid': conn.pid,
                'name': proc_name,
                'status': conn.status,
                'local': f"{local_ip}:{local_port}",
                'remote': f"{remote_ip}:{remote_port}" if remote_ip else "N/A"
            }

            process_connections[proc_name].append(conn_details)

            # Check for Chrome
            if is_chrome_process(proc_name) and conn.status == 'ESTABLISHED':
                chrome_connections.append(conn_details)

            # Check for Suspicious Ports
            if conn.status == 'LISTEN' and local_port:
                suspicion = check_suspicious_ports(local_port)
                if suspicion:
                    conn_details['reason'] = suspicion
                    suspicious_connections.append(conn_details)
            elif conn.status == 'ESTABLISHED' and remote_port:
                suspicion = check_suspicious_ports(remote_port)
                if suspicion:
                    conn_details['reason'] = suspicion
                    suspicious_connections.append(conn_details)

    # Report Chrome Connections
    if chrome_connections:
        logging.info("--- Active Chrome/Chromium Connections ---")
        for c in chrome_connections:
            logging.info(f"PID: {c['pid']} | Local: {c['local']} -> Remote: {c['remote']}")
    else:
        logging.info("No active Chrome/Chromium connections found.")

    # Report Suspicious Connections
    if suspicious_connections:
        logging.warning("--- SUSPICIOUS CONNECTIONS DETECTED ---")
        for s in suspicious_connections:
            logging.warning(f"PID: {s['pid']} ({s['name']}) | Status: {s['status']} | Local: {s['local']} -> Remote: {s['remote']} | Reason: {s['reason']}")
    else:
        logging.info("No suspicious connections detected on known bad ports.")

    logging.info("Network analysis complete.")

if __name__ == "__main__":
    analyze_connections()
