# Telematrix Default Provisioning Tool

A Python-based network provisioning automation tool designed to discover, identify, and configure Telematrix devices on local networks using automated TFTP-based configuration deployment.

## Project Overview

The `network_provision.py` script automates the bulk provisioning of Telematrix devices across network segments. It performs intelligent network discovery, device identification by vendor MAC address, and automated configuration deployment using TFTP protocols. This tool is designed for network administrators who need to efficiently provision multiple Telematrix devices with standardized configurations.

## Features

- **🔍 Network Discovery**: Automated scanning of IP ranges or subnets to identify active network hosts
- **🏷️ Device Identification**: Intelligent filtering of Telematrix devices using vendor-specific MAC address prefixes (`00:19:f3`)
- **🔐 Automated Authentication**: Streamlined Telnet login using default device credentials
- **📦 TFTP Configuration Deployment**: Automated download and application of device-specific configuration files
- **🔄 Device Management**: Automated device reload/reboot after successful configuration
- **📊 Comprehensive Logging**: Detailed activity logging for auditing, troubleshooting, and monitoring
- **🔁 Continuous Operation**: Persistent scanning with configurable intervals for ongoing device discovery

## Usage Instructions

### Basic Syntax

```bash
python network_provision.py <network_scope> <tftp_server_ip>
```

### Parameters

- **`network_scope`**: Define the target network range using one of two formats:
  - **CIDR notation**: `192.168.1.0/24` (scans entire subnet)
  - **IP range**: `192.168.1.100-192.168.1.150` (scans specific range)
- **`tftp_server_ip`**: IP address of the TFTP server hosting configuration files

### Command Examples

```bash
# Scan entire subnet
python network_provision.py 192.168.1.0/24 192.168.1.5

# Scan specific IP range
python network_provision.py 10.0.1.100-10.0.1.200 10.0.1.10

# Scan smaller subnet
python network_provision.py 172.16.50.0/28 172.16.50.1
```

## Application Logic

The provisioning process follows a systematic workflow designed for reliability and efficiency:

### 1. Network Scanning Phase
- **IP Scope Parsing**: Converts input parameters (CIDR or range) into a comprehensive list of target IP addresses
- **Host Discovery**: Performs ICMP ping tests to identify active network devices
- **MAC Address Resolution**: Uses ARP requests to obtain hardware addresses for responsive hosts

### 2. Device Identification Phase
- **Vendor Filtering**: Examines MAC addresses for Telematrix vendor prefix (`00:19:f3`)
- **Device Validation**: Confirms device accessibility and basic network connectivity

### 3. Telnet Authentication Phase
- **Connection Establishment**: Initiates Telnet sessions on port 23
- **Credential Authentication**: Attempts login using default credentials (`admin`/`admin`)
- **Session Validation**: Verifies successful shell access before proceeding

### 4. Configuration Provisioning Phase
- **TFTP Command Execution**: Sends device-specific download commands:
  ```
  download tftp -ip <tftp_server_ip> -file <mac_address>
  ```
- **Download Verification**: Monitors for success/failure messages from the device
- **Configuration Application**: Automatically triggers device reload upon successful download

### 5. Logging and Monitoring
- **Activity Tracking**: Records all operations, successes, and failures
- **Error Handling**: Captures and logs connection failures, timeouts, and authentication issues
- **Audit Trail**: Maintains comprehensive logs in `network_provision.log`

### 6. Continuous Operation
- **Persistent Scanning**: Continuously loops through the specified IP range
- **Interval Management**: Implements delays between scans to optimize network performance
- **Resource Management**: Properly closes connections and manages system resources

## Requirements

### System Requirements
- **Python**: Version 3.6 or higher
- **Operating System**: Linux, macOS, or Windows
- **Network Access**: Connectivity to target device networks and TFTP server
- **Privileges**: Administrative/root access may be required for ARP and ICMP operations

### Python Dependencies

Install required packages using pip:

```bash
pip install scapy
```

### Network Infrastructure Requirements
- **TFTP Server**: Accessible TFTP server with configuration files named by device MAC address
- **Network Connectivity**: Direct network access to target Telematrix devices
- **Firewall Configuration**: Ensure ports 23 (Telnet), 69 (TFTP), and ICMP are accessible

## Installation

1. **Clone or download** the repository:
   ```bash
   git clone <repository_url>
   cd telematrix_default
   ```

2. **Install dependencies**:
   ```bash
   pip install scapy
   ```

3. **Verify Python installation**:
   ```bash
   python --version  # Should be 3.6+
   ```

4. **Set up TFTP server** with configuration files named by MAC address (without colons)

## Important Notes

### Security Considerations
- ⚠️ **Default Credentials**: The script uses hardcoded default credentials (`admin`/`admin`)
- 🔒 **Network Security**: Telnet traffic is unencrypted; consider network isolation
- 🛡️ **Access Control**: Limit script execution to authorized network administrators
- 📋 **Change Default Passwords**: Ensure devices have their default passwords changed after provisioning

### Operational Considerations
- 🔧 **Administrative Privileges**: May require root/administrator privileges for raw packet operations
- 🔄 **Continuous Operation**: Script runs indefinitely; use Ctrl+C to stop execution
- 📊 **Log Management**: Monitor `network_provision.log` for provisioning status and errors
- 🌐 **Network Impact**: Consider network load during large-scale provisioning operations

### TFTP Configuration Files
- Configuration files must be named using the device MAC address (without colons)
- Example: For device with MAC `00:19:f3:12:34:56`, file should be named `0019f3123456`
- Ensure TFTP server has appropriate read permissions for configuration files

### Troubleshooting
- **Permission Errors**: Run with sudo/administrator privileges if ARP/ICMP operations fail
- **Network Timeouts**: Verify network connectivity and firewall settings
- **TFTP Failures**: Confirm TFTP server accessibility and file naming conventions
- **Device Access**: Verify default credentials haven't been changed on target devices

## Log File Analysis

The script generates detailed logs in `network_provision.log` with timestamps for:
- Device discovery events
- Authentication attempts
- Configuration download status
- Error conditions and exceptions
- Device reboot confirmations

Monitor this file for provisioning progress and troubleshooting information.
