# plan of action: 1. Scan default network scope and check alive IPs with mac dddress filter as Telematrix devices.
# If device has vendor mac - try to login via telnet with default login/password and apply basic provisionning settings, then restart the phone.
import ipaddress
import time
from scapy.all import ARP, Ether, srp, ICMP, IP, sr1
import telnetlib

def get_mac(ip):
    """
    Returns the MAC address for a given IP in the local network using ARP.
    """
    arp_req = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    answered = srp(broadcast/arp_req, timeout=2, verbose=False)[0]
    for sent, received in answered:
        return received.hwsrc
    return None

def is_alive(ip):
    """
    Returns True if the host at IP responds to ICMP ping.
    """
    pkt = IP(dst=ip)/ICMP()
    reply = sr1(pkt, timeout=1, verbose=False)
    return reply is not None

def telnet_login(ip, username="admin", password="admin"):
    """
    Attempts Telnet login, returns True if successful, False otherwise.
    """
    try:
        tn = telnetlib.Telnet(ip, 23, timeout=5)
        tn.read_until(b"login: ", timeout=5)
        tn.write(username.encode('ascii') + b"\n")
        tn.read_until(b"Password: ", timeout=5)
        tn.write(password.encode('ascii') + b"\n")
        # Wait for shell prompt (could be '#', '$', etc.), adjust as needed
        idx, obj, res = tn.expect([b'#', b'>', b'\$'], timeout=5)
        tn.close()
        return idx != -1
    except Exception as e:
        print(f"Telnet error on {ip}: {e}")
        return False

def scan_network(network_scope):
    net = ipaddress.ip_network(network_scope, strict=False)
    while True:
        for ip in net.hosts():
            ip_str = str(ip)
            if is_alive(ip_str):
                mac = get_mac(ip_str)
                if mac and mac.lower().startswith("00:19:f3"):
                    print(f"Device found: {ip_str} - {mac}")
                    if telnet_login(ip_str):
                        print(f"Telnet login successful for {ip_str}")
                    else:
                        print(f"Telnet login failed for {ip_str}")
            time.sleep(0.1)  # Avoid hammering the network
        time.sleep(5)  # Wait before rescanning

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python network_provision.py <network/mask>")
        sys.exit(1)
    network_scope = sys.argv[1]
    scan_network(network_scope)
