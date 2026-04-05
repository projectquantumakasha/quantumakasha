import psutil
import socket

def get_process_name(pid):
    try:
        process = psutil.Process(pid)
        return process.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None

def resolve_ip(ip_address):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror:
        return "Unknown"

def monitor_network():
    print("Active Network Connections:")
    print("{:<10} {:<25} {:<25} {:<15} {:<30}".format("PID", "Local Address", "Remote Address", "Status", "Process Name / Hostname"))
    print("-" * 110)

    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'ESTABLISHED':
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
            pid = conn.pid

            if pid:
                process_name = get_process_name(pid)
                if process_name and ('chrome' in process_name.lower() or 'chromium' in process_name.lower()):
                    hostname = resolve_ip(conn.raddr.ip) if conn.raddr else "N/A"
                    print("{:<10} {:<25} {:<25} {:<15} {:<30}".format(pid, laddr, raddr, conn.status, f"{process_name} ({hostname})"))
                else:
                    print("{:<10} {:<25} {:<25} {:<15} {:<30}".format(pid, laddr, raddr, conn.status, str(process_name)))
            else:
                 print("{:<10} {:<25} {:<25} {:<15} {:<30}".format("N/A", laddr, raddr, conn.status, "N/A"))

if __name__ == "__main__":
    monitor_network()
