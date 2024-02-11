import logging
from scapy.layers.inet import *
from scapy.sendrecv import sr1
import sys
import time
import threading


# Setup logging
logging.basicConfig(filename='port.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

# Constants
TARGET_IP = "127.0.0.1"  # Placeholder IP, will be replaced with user input
PORT_RANGE = (130, 140)
TIMEOUT = 0.5
SPINNER = ['|', '/', '-', '\\']
SPINNER_INTERVAL = 0.1  # Spinner update interval in seconds

# Global variables
open_ports = []
closed_ports = []  # Track closed ports if needed

# Global variable to control the spinner thread
spinner_active = False


def spinner():
    """
    Spinner function to run in a separate thread.
    """
    spinner_chars = ['|', '/', '-', '\\']
    while spinner_active:
        for char in spinner_chars:
            sys.stdout.write(f'\r{char} Scanning...')
            sys.stdout.flush()
            time.sleep(SPINNER_INTERVAL)
    sys.stdout.write('\rDone scanning.        \n')  # Clear the spinner line


def print_spinner_and_status(port, status):
    """
    Prints the spinner and the current port status.
    """
    spinner_char = SPINNER[port % len(SPINNER)]
    sys.stdout.write(f"\r{spinner_char} Scanning port {port}... {status}")
    sys.stdout.flush()


def finalize_scan():
    """
    Prints the summary of the scan results.
    """
    sys.stdout.write("\nScan Completed.\n")
    sys.stdout.write(f"Summary:\nTotal ports scanned: {len(open_ports) + len(closed_ports)}\n")
    sys.stdout.write(f"Open ports: {len(open_ports)}\n")
    sys.stdout.write(f"Closed ports: {len(closed_ports)}\n")
    sys.stdout.write("Open ports are: " + ", ".join(map(str, open_ports)) + "\n")


def check_tcp_flags(tcp_flags):
    """
    Checks the TCP flags to determine the state of the port.
    """
    syn_flag_set = tcp_flags & 0x02 != 0
    ack_flag_set = tcp_flags & 0x10 != 0

    if syn_flag_set and ack_flag_set:
        return "open"
    elif tcp_flags & 0x04 != 0:
        return "closed"
    else:
        return "unexpected"


def scan_port(ip, port):
    """
    Sends a SYN packet to a specific port on the target IP and checks for a response.
    """
    src_port = RandShort()
    response = sr1(IP(dst=ip) / TCP(sport=src_port, dport=port, flags="S"), timeout=TIMEOUT, verbose=0)

    if response and response.haslayer(TCP):
        tcp_flags = response.getlayer(TCP).flags
        port_state = check_tcp_flags(tcp_flags)

        if port_state == "open":
            logger.info(f"Port {port} is open on {ip}. [SYN-ACK received]")
            open_ports.append(port)
            return True
        else:
            closed_ports.append(port)
            logger.debug(f"Port {port} is closed or filtered on {ip}.")
            return False
    else:
        logger.debug(f"No response received for port {port} on {ip}.")
        closed_ports.append(port)
        return False


def main():
    global spinner_active
    logger.info(f"Starting scan on {TARGET_IP}")

    # Start the spinner thread
    spinner_active = True
    spinner_thread = threading.Thread(target=spinner)
    spinner_thread.start()

    for port in range(PORT_RANGE[0], PORT_RANGE[1] + 1):
        scan_port(TARGET_IP, port)

    # Stop the spinner and wait for the thread to finish
    spinner_active = False
    spinner_thread.join()

    finalize_scan()


if __name__ == "__main__":
    main()
