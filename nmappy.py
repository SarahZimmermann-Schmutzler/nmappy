"""
NMAPPY - The program is based on the basic functionality of nmap. It scans ports and indicates which of the scanned ports is open or closed. 
For thirst 100 ports to scan, it is also specified which application is running on the port.
"""

import socket
import argparse
import threading
from queue import Queue


# dictionary of service identification probes for common ports
SERVICE_PROBES: dict[int, bytes] = {
    20: b"NOOP\r\n",                       # FTP Data Transfer
    21: b"HELLO\r\n",                      # FTP Control - Often responds with welcome message
    22: b"\n",                             # SSH - Often responds with version
    23: b"\r\n",                           # Telnet - Often responds with login prompt
    25: b"EHLO example.com\r\n",           # SMTP
    53: b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",  # DNS - Simple query
    80: b"HEAD / HTTP/1.0\r\n\r\n",        # HTTP
    110: b"USER test\r\n",                 # POP3
    143: b"TAG LOGIN test test\r\n",       # IMAP
    443: b"\x16\x03\x01\x00\x01\x01",      # HTTPS - SSL/TLS Client Hello
    587: b"EHLO example.com\r\n",          # SMTP Secure
    3306: b"\x00",                         # MySQL - Often responds with server version
    3389: b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x03\x00\x00\x00",  # Remote Desktop - RDP Negotiation Request
    5900: b"RFB 003.003\n",                # VNC - Protocol version request
    8080: b"HEAD / HTTP/1.0\r\n\r\n",      # HTTP Alternate (often used by proxy servers)
}


# dictionary of keywords to identify services based on port responses
SERVICE_KEYWORDS: dict[str, str] = {
    "HTTP": "HTTP",                         # Web servers
    "220": "FTP",                           # FTP server response code
    "FTP": "FTP",                           # FTP keyword
    "SSH": "SSH",                           # Secure Shell
    "Telnet": "Telnet",                     # Telnet protocol
    "Login": "Telnet",                      # Telnet login prompt
    "POP3": "POP3",                         # POP3 email protocol
    "IMAP": "IMAP",                         # IMAP email protocol
    "SMTP": "SMTP",                         # Simple Mail Transfer Protocol
    "MySQL": "MySQL",                       # MySQL database server
    "RFB": "VNC",                           # Virtual Network Computing (VNC)
    "RDP": "Remote Desktop",                # Remote Desktop Protocol
    "HTTPS": "HTTPS"                        # Secure web servers
}


def identify_service(sock: socket.socket, port: int) -> str:
    """
    Identifies the service running on a given port by sending protocol-specific probes. 
    The service identification will only be done for the first 100 ports of the given port-range.

    Args:
        sock (socket.socket): The socket connected to the target.
        port (int): The port to be identified.

    Returns:
        str: The name of the identified service or "Unknown" if no match is found.
    """
    try:
        # sends specific probe if port has a common protocol
        if port in SERVICE_PROBES:
            sock.sendall(SERVICE_PROBES[port])
            # decodes with ignore to handle binary responses
            response = sock.recv(1024).decode(errors="ignore")

            # analyzes a fragment of the response for known service keywords
            for keyword, service in SERVICE_KEYWORDS.items():
                if keyword in response:
                    return service

        return "Unknown"

    except Exception:
        return "Unknown"


def scan_port(ip: str, port: int, verbose: bool = False) -> None:
    """
    Scans a single port to check if it's open and optionally identifies the service.
    It is used in the function threader()

    Args:
        ip (str): The IP address of the target.
        port (int): The port number to scan.
        verbose (bool): Whether to identify the service if the port is open.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            # running service identification only if verbose is True (for first 100 ports)
            if verbose:
                service_name = identify_service(sock, port)
            else:
                service_name = "Unknown"
            
            print(f"Port {port} is open (Service: {service_name})")
        # else:
        #     print(f"Port {port} is closed")
        sock.close()
    except Exception as e:
        print(f"Error scanning port {port}: {e}")


def resolve_dns(host: str) -> str | None:
    """
    Resolves a DNS address to an IP address if it is necessary.

    Args:
        host (str): The DNS hostname to resolve.

    Returns:
        str | None: The resolved IP address or None if resolution fails.
    """
    try:
        ip = socket.gethostbyname(host)
        print(f"Resolved IP for {host}: {ip}")
        return ip
    except socket.gaierror:
        print(f"Error: Unable to resolve {host}")
        return None


def threader(queue: Queue, ip: str) -> None:
    """
    Thread worker function that retrieves ports from a queue and scans them parallel in several threads (max. 100).
    It is used in threaded_port_scan().

    Args:
        queue (Queue): A queue containing the ports to scan.
        ip (str): The IP address of the target.
    """
    while True:
        worker = queue.get()
        scan_port(ip, worker, verbose=(worker <= 100))
        queue.task_done()


def threaded_port_scan(ip: str, min_port: int, max_port: int) -> None:
    """
    Performs a multithreaded port scan on a given range of ports.
    Offers the framework conditions for the multithreading port scan - threader(), scan_port()

    Args:
        ip (str): The IP address of the target.
        min_port (int): The minimum port number to scan.
        max_port (int): The maximum port number to scan.
    """
    print(f"Scanning IP: {ip} from port {min_port} to {max_port} using threads...\n")

    # calculates the total number of ports to scan
    total_ports = max_port - min_port + 1
    
    # limits the maximum number of threads to 100
    max_threads = min(100, total_ports)
    
    # defines a Queue that saves later all ports that has to be scanned
    queue = Queue()
    
    # starts max. 100 threads that should all execute the function threader(), i.e. function threader() is executed 100 times in parallel
    for _ in range(max_threads):
        thread = threading.Thread(target=threader, args=(queue, ip), daemon=True)
        thread.start()

    # fills the que with the ports that has to be scanned
    for port in range(min_port, max_port + 1):
        queue.put(port)
    
    # waits until all ports are scanned
    queue.join()


def main() -> None:
    """
    The main function that serves as the entry point for the port scanner script.

    This function performs the following tasks:
    1. Parses command-line arguments to determine the target and port range to scan.
    2. Resolves the target hostname or DNS address to an IP address, if necessary.
    3. Initiates a multithreaded port scan on the specified IP address and port range or all ports.

    Command-line Arguments see below.

    Function Workflow:
    - Parses arguments using `argparse`.
    - Validates and resolves the target's IP address using `resolve_dns()`.
    - If resolution fails, the function exits.
    - Calls `threaded_port_scan()` to perform the scan within the specified port range.

    Returns:
        None: The function prints the scan results to the console and does not return any value.

    Example Usage:
        python nmappy.py 192.168.1.1 -p --min 20 --max 80
        python nmappy.py example.com -p
    """
    parser = argparse.ArgumentParser(description="Simple Port Scanner")

    # target address; positional argument 
    parser.add_argument("target", help="Target IP or DNS address")
    # flag to scan all ports; required
    parser.add_argument("-p", required=True, action="store_true", help="Use -p to scan all ports; use -p with --min and --max to specify a range.")
    # optional range to specify the ports that should be scanned
    parser.add_argument("--min", type=int, default=1, help="Minimum port number to scan (default: 1)")
    parser.add_argument("--max", type=int, default=65535, help="Maximum port number to scan (default: 65535)")

    args = parser.parse_args()

    ip = resolve_dns(args.target)
    if ip is None:
        return
    
    threaded_port_scan(ip, args.min, args.max)

if __name__ == "__main__":
    main()