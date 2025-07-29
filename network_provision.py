# plan of action: 1. Scan default network scope and check alive IPs with mac dddress filter as Telematrix devices.
# If device has vendor mac - try to login via telnet with default login/password and apply basic provisionning settings, then restart the phone.
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning) 
import time
from scapy.all import ARP, Ether, srp, ICMP, IP, sr1
import telnetlib
import ipaddress
import logging
import sys
import re


logging.basicConfig(
    filename='network_provision.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)

def parse_ip_scope(scope):
    # Detect network/mask format
    if "/" in scope:
        net = ipaddress.ip_network(scope, strict=False)
        return [str(ip) for ip in net.hosts()]
    # Detect ip range format: start_ip-final_ip
    elif "-" in scope:
        start_ip, final_ip = scope.split("-")
        start_int = int(ipaddress.IPv4Address(start_ip.strip()))
        final_int = int(ipaddress.IPv4Address(final_ip.strip()))
        return [str(ipaddress.IPv4Address(ip))
                for ip in range(start_int, final_int + 1)]
    else:
        raise ValueError("Scope must be in 'network/mask' or 'start_ip-final_ip' format")
        
def get_mac(ip, username="admin", password="admin", timeout=5):
    """
    Connect to a device via Telnet at the given IP, log in,
    send 'show network', and extract the MAC address from the output.
    Returns:
        str: MAC address string (e.g. '00:19:f3:06:79:ae'), or None if not found.
    """
    try:
        tn = telnetlib.Telnet(ip, timeout=timeout)
        tn.read_until(b"Login: ")
        tn.write(username.encode('ascii') + b"\n")
        tn.read_until(b"Password: ")
        tn.write(password.encode('ascii') + b"\n")
        tn.read_until(b"#")  # Wait for shell prompt

        tn.write(b"show network\n")
        output = tn.read_until(b"#", timeout=timeout).decode('ascii')

        # Search for the line containing the MAC address
        match = re.search(r"Mac Address\s*:\s*([0-9a-fA-F:]{17})", output)
        if match:
            return match.group(1)
        else:
            return None
    except Exception as e:
        logging.error(f"{ip}: Telnet session error: {e}")
        return None

def is_alive(ip):
    """
    Returns True if the host at IP responds to ICMP ping.
    """
    pkt = IP(dst=ip)/ICMP()
    reply = sr1(pkt, timeout=1, verbose=False)
    return reply is not None

def telnet_download_and_reload(ip, mac, tftp_server, username="admin", password="admin"):
    try:
        tn = telnetlib.Telnet(ip, 23, timeout=5)
        tn.read_until(b"Login: ", timeout=5)
        tn.write(username.encode('ascii') + b"\n")
        tn.read_until(b"Password: ", timeout=5)
        tn.write(password.encode('ascii') + b"\n")
        idx, obj, res = tn.expect([b'#'], timeout=5)
        if idx == -1:
            logging.warning(f"{ip}: Telnet prompt not found after login.")
            tn.close()
            return
        # Build command
        mac = mac.replace(';', '').lower()
        cmd = f"download tftp -ip {tftp_server} -file {mac}\n"
        tn.write(cmd.encode('ascii'))
        # Wait for reply
        reply = tn.read_until(b"Download config file successfully!", timeout=10)
        if b"Download config file successfully!" in reply:
            logging.info(f"{ip}: Download config file successfully!")
            tn.write(b"reload\n")
            tn.close()
            return
        elif b"Download config file failed!" in reply:
            logging.warning(f"{ip}: Download config file failed!")
            tn.close()
            return
        else:
            # Timeout or unexpected response
            logging.warning(f"{ip}: Unexpected or no reply after download command.")
            tn.close()
            return
    except Exception as e:
        logging.error(f"{ip}: Telnet session error: {e}")
        return
        
def scan_network(scope, tftp_server):
    ip_list = parse_ip_scope(scope)
    for ip_str in ip_list:
            if is_alive(ip_str):
                mac = get_mac(ip_str)
                if mac and mac.lower().startswith("00:19:f3"):
                    logging.info(f"Device found: {ip_str} - {mac}")
                    if telnet_download_and_reload(ip_str, mac, tftp_server):
                        logging.info(f"Telnet command successful for {ip_str}")
                    else:
                        logging.warning(f"Telnet login failed for {ip_str}")
            time.sleep(0.1)
  
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 network_provision.py <network/mask or start_ip-final_ip> <tftp_server_ip>")
        sys.exit(1)
    scope = sys.argv[1]
    tftp_server = sys.argv[2]
    scan_network(scope, tftp_server)
