import logging
import socket
from scapy.all import IP, TCP, sr1


TARGET = "127.0.0.1"
PORT_START = 0
PORT_END = 1024
TIMEOUT_DURATION = 0.5
CLOSE_PORT = 0x14
OPEN_PORT = 0x12


def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def main():
    if is_valid_ip(TARGET):
        print("valid ip address")
        logger.info(f"Starting scan on {TARGET} (Range: {PORT_START}-{PORT_END})")
        print("Starting scan on ", TARGET + " through ", str(PORT_START) + " through ", str(PORT_END))
        print("the open ports are...")
        open_ports = []
        for port in range(PORT_START, PORT_END + 1):
            try:
                syn_packet = IP(dst=TARGET) / TCP(dport=port, flags="S")
                response = sr1(syn_packet, timeout=TIMEOUT_DURATION, verbose=0)
                if response is None:
                    logger.debug(f"Port {port}: No response")
                elif response.haslayer(TCP):
                    tcp_layer = response.getlayer(TCP)
                    if tcp_layer.flags == OPEN_PORT:
                        logger.info(f"[+] Port {port} is OPEN")
                        open_ports.append(port)
                        print("port " + str(port) + " is open")
                    elif tcp_layer.flags == CLOSE_PORT:
                        logger.debug(f"Port {port}: Closed")
            except Exception as error:
                logger.error(f"Error scanning port {port}: {error}")
        logger.info("--- Scan Results ---")
        if open_ports:
            logger.info(f"Open ports found: {open_ports}")
            print("all the open ports are: ", open_ports)
        else:
            logger.info("No open ports found in the specified range.")
            print("No open ports found opened in the specified range.")
    else:
        print("Invalid IP Address")


if __name__ == "__main__":
    logging.basicConfig(filename="6.19 project .log",
                        format='%(asctime)s %(message)s',
                        filemode='w')

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    try:
        assert is_valid_ip("127.0.0.") is False, "Invalid IP Address"
        assert 0 <= PORT_START <= 65535 and 0 <= PORT_END <= 65535, "Ports must be between 0-65535"
        assert PORT_START <= PORT_END, "Start port must be less than or equal to end port"
        logger.info("all asserts passed")
        main()
    except AssertionError as e:
        logger.error(f"Configuration Error: {e}")
    except PermissionError:
        logger.error("Permission Denied: Please run as root/administrator (required for Scapy).")
    except Exception as e:
        logger.critical(f"An unexpected error occurred: {str(e)}")
