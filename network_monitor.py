import psutil

def get_process_name(pid):
    try:
        process = psutil.Process(pid)
        return process.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "Unknown"

def main():
    print(f"{'PID':<8} | {'Process Name':<25} | {'Local Address':<25} | {'Remote Address':<25} | {'Status':<15}")
    print("-" * 105)

    try:
        connections = psutil.net_connections(kind='inet')
    except psutil.AccessDenied:
        print("Run with elevated privileges (sudo) to see all connections.")
        # On some systems net_connections requires root. Fall back to an empty list.
        connections = []

    for conn in connections:
        pid = conn.pid
        process_name = get_process_name(pid) if pid else "Unknown"

        local_address = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
        remote_address = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
        status = conn.status

        print(f"{str(pid):<8} | {process_name:<25} | {local_address:<25} | {remote_address:<25} | {status:<15}")

if __name__ == "__main__":
    main()
