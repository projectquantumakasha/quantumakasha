import psutil
import socket
import logging

logging.basicConfig(level=logging.INFO, format='%(message)s')

TELEMETRY_KEYWORDS = [
    'telemetry', 'analytics', 'tracking', 'metrics', 'logger', 'collector',
    'google-analytics', 'app-measurement', 'events', 'stats', 'ping'
]

TELEMETRY_DOMAINS = [
    '1e100.net',                # Google
    'google-analytics.com',     # Google Analytics
    'app-measurement.com',      # Google App Measurement
    'doubleclick.net',          # Google Ads
    'clients4.google.com',      # Google Clients
    'settings.crashlytics.com', # Crashlytics
    'events.data.microsoft.com',# Microsoft Telemetry
    'vortex.data.microsoft.com',# Microsoft Telemetry
    'watson.telemetry.microsoft.com', # Microsoft Telemetry
    'pipe.skype.com',           # Skype Telemetry
    'browser.events.data.msn.com', # MSN Telemetry
]

def check_domain_for_telemetry(domain):
    domain_lower = domain.lower()
    for keyword in TELEMETRY_KEYWORDS:
        if keyword in domain_lower:
            return True, f"Keyword match: {keyword}"
    for t_domain in TELEMETRY_DOMAINS:
        if t_domain in domain_lower:
            return True, f"Domain match: {t_domain}"
    return False, ""

def get_process_name(pid):
    try:
        process = psutil.Process(pid)
        return process.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "Unknown"

def monitor_connections():
    logging.info(f"{'PID':<8} | {'Process':<20} | {'Local Address':<22} | {'Remote Address':<22} | {'Resolved Domain':<40} | {'Status'}")
    logging.info("-" * 140)

    try:
        connections = psutil.net_connections(kind='inet')
    except psutil.AccessDenied:
        logging.warning("Access denied. Please run as root (sudo) for full visibility.")
        return

    for conn in connections:
        if conn.status == 'ESTABLISHED':
            pid = conn.pid
            process_name = get_process_name(pid) if pid else "Unknown"

            laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
            if conn.raddr:
                raddr_ip = conn.raddr.ip
                raddr_port = conn.raddr.port
                raddr = f"{raddr_ip}:{raddr_port}"

                try:
                    domain, _, _ = socket.gethostbyaddr(raddr_ip)
                except socket.herror:
                    domain = raddr_ip

                is_telemetry, reason = check_domain_for_telemetry(domain)
                status = f"FLAGGED: {reason}" if is_telemetry else "OK"

                logging.info(f"{pid or '-':<8} | {process_name:<20} | {laddr:<22} | {raddr:<22} | {domain:<40} | {status}")

if __name__ == "__main__":
    monitor_connections()
