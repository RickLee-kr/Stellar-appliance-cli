# Stellar Appliance CLI

A command-line interface (CLI) tool for Stellar Cyber Appliance. It allows you to manage network settings, NTP configuration, firewall rules, and more on KVM hosts.

## Purpose

This CLI tool was developed to perform the following tasks in Stellar Cyber Appliance environments:

- **Network Configuration Management**: IP address, Gateway, and DNS server configuration
- **NTP Configuration Management**: Support for various NTP implementations (ntpsec, chrony, systemd-timesyncd)
- **Firewall Rule Management**: Access Control List (ACL) management using iptables
- **System Information Query**: Hostname, service status, routing tables, etc.
- **System Configuration**: Timezone, time, patch management, etc.

## Key Features

### 1. Network Configuration Management

#### Interface Information Display and Configuration
```bash
show interface              # Display all network interface information
set interface <interface> ip <IP> <netmask> [gateway]  # Set IP address
set interface <interface> gateway <gateway>            # Set Gateway
set interface <interface> dns <dns1> [dns2 ...]        # Set DNS servers
unset interface <interface>                            # Remove interface configuration
```

#### DNS Server Display and Configuration
```bash
show dns                   # Display currently configured DNS servers
set dns <interface> <dns1> [dns2 ...]  # Set DNS servers
```

#### Gateway Display
```bash
show gateway               # Display default Gateway information
```

### 2. NTP Configuration Management

Automatically detects and supports various NTP implementations:
- **ntpsec**: `/etc/ntpsec/ntp.conf`
- **chrony**: `/etc/chrony/chrony.conf`
- **systemd-timesyncd**: `/etc/systemd/timesyncd.conf`
- **legacy ntp**: `/etc/ntp.conf`

```bash
show ntp                   # Display current NTP configuration and server information
set ntp <server>           # Add NTP server
unset ntp <server>         # Remove NTP server
```

**Features:**
- Automatically recognizes NTP configurations set by installer scripts
- Automatically detects active NTP service
- Automatically restarts NTP service

### 3. Access Control List (ACL) Management

Firewall rule management using iptables:

```bash
show acl                   # Display current iptables INPUT chain rules
set acl allow <IP/network> <port> [port2 ...] | all [description]  # Add allow rule
set acl deny <IP/network> <port> [port2 ...] | all [description]   # Add deny rule
unset acl <IP/network> <port> [port2 ...] | all                    # Remove rule
```

**Examples:**
```bash
# Allow specific port for single IP
set acl allow 192.168.1.100 22 "Admin SSH access"

# Allow multiple ports for network
set acl allow 192.168.1.0/24 80 443 "Web servers"

# Allow all ports for network
set acl allow 10.0.0.0/8 all "Internal network"

# Remove rule
unset acl 192.168.1.100 22
```

**Features:**
- Supports IP addresses or CIDR networks (e.g., `192.168.1.0/24`)
- Supports single port, multiple ports, or all ports
- Optional description/comment for each rule
- View rules with descriptions using `show acl` command
- Local interface IPs (e.g., 192.168.0.100) are always allowed and cannot be blocked
- Default policy is ACCEPT when no user-defined ACL rules are configured
- Local interface IP rules are hidden from `show acl` output and cannot be removed

### 4. System Information Display

```bash
show version               # Display system information
show hostname              # Display hostname
show service               # Display service status
show timezone              # Display timezone information
show time                  # Display system time
show route                 # Display routing table
```

### 5. System Configuration

```bash
set timezone <timezone>    # Set timezone
set time <YYYY-MM-DD HH:MM:SS>  # Set system time
set hostname <hostname>    # Set hostname
set password               # Change administrator password
```

### 6. Service Management

```bash
start <service>            # Start service
restart <service>         # Restart service
shutdown <service>         # Shutdown service
```

### 7. Other Features

```bash
show autostart             # Display VM auto-start configuration
set autostart <vm> <on|off>  # Configure VM auto-start
show patch_history         # Display patch application history
set patches <patch_file>   # Apply patches
monitor                    # Monitor VM resources and system status
```

## Installation

### Requirements

- Python 3.10 or higher
- Linux environment (Ubuntu 16.04 or higher recommended)
- sudo privileges

### Installation Steps

1. Clone the repository:
```bash
git clone https://github.com/RickLee-kr/Stellar-appliance-cli.git
cd Stellar-appliance-cli
```

2. Create and activate virtual environment (recommended):
```bash
python3 -m venv venv
source venv/bin/activate
```

3. Install the package:
```bash
pip install -e .
```

## Usage

Run the CLI:
```bash
aella_cli
```

Or run directly as a Python module:
```bash
python -m dp_cli.aella_cli_aio_appliance
```

### Command Structure

The CLI uses the following command structure:

```
<command> <subcommand> [parameters]
```

Main commands:
- `show <item>`: Display information
- `set <item> <parameters>`: Change configuration
- `unset <item> <parameters>`: Remove configuration
- `start <service>`: Start service
- `restart <service>`: Restart service
- `shutdown <service>`: Shutdown service

### Help

```bash
help                    # List all commands
help <command>          # Show help for specific command
show <item> ?           # Show usage for specific item
set <item> ?            # Show usage for set command
```

## Supported Installer Scripts

This CLI is compatible with the following installer scripts:

- Ubuntu 16.04 base DP installer
- Ubuntu 24.04 base DP Installer
- AIO-Sensor installer
- xdr-sensor-installer
- xdr-6000-sensor-installer

The CLI can automatically recognize and manage network configurations and NTP settings set by these installer scripts.

## Network Configuration File Structure

The CLI manages the following files:

- `/etc/network/interfaces`: Main network interface configuration
- `/etc/network/interfaces.d/*.cfg`: Per-interface configuration files

## NTP Configuration Files

The CLI supports the following NTP configuration files:

- `/etc/ntpsec/ntp.conf`: ntpsec configuration
- `/etc/chrony/chrony.conf`: chrony configuration
- `/etc/systemd/timesyncd.conf`: systemd-timesyncd configuration
- `/etc/ntp.conf`: legacy ntp configuration

## ACL (iptables) Rules

ACL rules are added to the iptables INPUT chain. To make rules persistent, use the following commands:

```bash
sudo iptables-save > /etc/iptables/rules.v4
```

Or for Ubuntu:
```bash
sudo netfilter-persistent save
```

## Important Notes

- After changing network settings, you must restart the interface for changes to take effect:
  ```bash
  set interface <interface> restart
  ```

- NTP service is automatically restarted when NTP configuration is changed.

- ACL rules are applied immediately, but you must save iptables rules to persist them after system reboot.

- Some commands may require `sudo` privileges.

- Local interface IPs (e.g., 192.168.0.100) are always allowed regardless of ACL deny rules. Traffic to local interface IPs cannot be blocked.

- When no user-defined ACL rules are configured, the default policy is ACCEPT (all traffic allowed).

- Local interface IP rules are hidden from `show acl` output and cannot be removed using `unset acl`.

## License

Copyright (c) 2026, Stellar Cyber Inc.

## Contributing

Please submit issue reports or feature suggestions through GitHub Issues.

## Related Projects

- [OpenXDR KVM Installer](https://github.com/RickLee-kr/OpenXDR-KVM-Installer): KVM host installation scripts
