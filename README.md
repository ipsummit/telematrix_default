# telematrix_default
Overview
network_provision.py is a Python script designed to automate the provisioning of Telematrix devices on a local network. It scans a specified IP range or subnet, identifies devices by their MAC address, attempts Telnet login, and sends provisioning commands to download configuration files via TFTP and reload the device.

Features
Network Scanning: Scans a network or IP range to find live hosts.
Device Identification: Filters devices by MAC address prefix (00:19:f3), identifying Telematrix devices.
Automated Provisioning: Logs in to devices via Telnet with default credentials, sends configuration download commands, and reboots devices.
Logging: All actions and errors are logged to network_provision.log for troubleshooting and auditing.
Usage
bash
python network_provision.py <network/mask or start_ip-final_ip> <tftp_server_ip>
<network/mask>: Example 192.168.1.0/24
start_ip-final_ip: Example 192.168.1.100-192.168.1.150
<tftp_server_ip>: IP address of your TFTP server hosting configuration files
How It Works
Parse IP Scope: Accepts a subnet or IP range and generates a list of target IPs.
Scan Devices: For each IP, checks if the host is alive (ICMP ping) and retrieves its MAC address (ARP).
Filter Telematrix Devices: Continues only if the MAC address matches the Telematrix vendor prefix.
Telnet Login: Attempts to log in with default credentials (admin/admin).
Provisioning:
Upon successful login, sends the command:
Code
download tftp -ip <tftp_server_ip> -file <mac>
Waits for a success message.
If successful, sends a reload command to reboot the device.
Logging: All actions and errors are written to network_provision.log.
Requirements
Python 3
scapy library (pip install scapy)
Network access to the target devices and TFTP server
Example
bash
python network_provision.py 192.168.1.0/24 192.168.1.5
This command will scan all hosts in 192.168.1.0/24 and provision Telematrix devices using the TFTP server at 192.168.1.5.

Notes
Run as administrator/root if required to send ARP and ICMP packets.
The script will continually loop over the specified IP range/subnet.
Default Telnet credentials are hardcoded as admin/admin.
