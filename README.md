# Stellar Appliance CLI

A command-line interface (CLI) tool for Stellar Cyber Appliance. It allows you to manage network settings, NTP configuration, firewall rules, and more on KVM hosts running OpenXDR Data Processor and Sensor components.

## Overview

The Stellar Appliance CLI provides a unified interface for managing KVM hosts deployed using the OpenXDR KVM Installer scripts. It automatically recognizes and manages configurations set by the installer scripts, making it easy to maintain and configure your OpenXDR deployment.

## Purpose

This CLI tool was developed to perform the following tasks in Stellar Cyber Appliance environments:

- **Network Configuration Management**: IP address, Gateway, and DNS server configuration
- **NTP Configuration Management**: Support for various NTP implementations (ntpsec, chrony, systemd-timesyncd)
- **Firewall Rule Management**: Access Control List (ACL) management using iptables
- **System Information Query**: Hostname, service status, routing tables, VM status, etc.
- **System Configuration**: Timezone, time, patch management, VM auto-start, etc.
- **VM Management**: Monitor VM resources, access VM consoles, manage VM auto-start

## Key Features

### 1. Network Configuration Management

#### Interface Information Display and Configuration
```bash
show interface              # Display all network interface information
set interface <interface> ip <IP/Mask> [gateway <IP>] [dns <dns1> ...]  # Set IP address
set interface <interface> gateway <gateway>            # Set Gateway
set interface <interface> dns <dns1> [dns2 ...]        # Set DNS servers
set interface <interface> restart                      # Apply changes (restart iface)
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

Firewall rule management using iptables (staged, apply required):

```bash
show acl                                      # Display current AELLA-managed rules
set acl policy                                # Initialize ACL mode and interface
set acl <IP/network> <port|icmp|ping|all> [description]  # Stage rule
set acl apply [--reset]                       # Apply staged rules
unset acl <IP/network> <port|icmp|ping|all>   # Remove rule (staged + live)
```

**Examples:**
```bash
# Initialize policy (select whitelist/blacklist + interface)
set acl policy

# Allow access to port 22 from single IP
set acl 192.168.1.100 22 "Admin SSH access"

# Allow access to multiple ports from network
set acl 192.168.1.0/24 80 443 "Web servers"

# Allow ICMP ping
set acl 192.168.1.10 icmp "Ping allowed"

# Apply staged rules
set acl apply

# Remove rule
unset acl 192.168.1.100 22
```

**Features:**
- Controls access **from** source IP addresses or CIDR networks (e.g., `192.168.1.0/24`) **to** destination ports
- Supports single port, multiple ports, icmp/ping, or all
- Optional description/comment for each rule
- `set acl apply` is required to activate staged rules
- `set acl apply --reset` rebuilds rules from staging
- `show acl` displays AELLA-managed chain entries in order
- Local interface IPs (e.g., 127.0.0.1, 192.168.0.100, 192.168.122.1) are always allowed and cannot be blocked
- Local interface IP rules are hidden from `show acl` output and cannot be removed using `unset acl`

**Note:** ACL rules control incoming traffic. For example, `set acl 192.168.1.100 22` allows access **from** 192.168.1.100 **to** port 22 on this KVM host after `set acl apply`.

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

### 7. VM Management

```bash
console <vm>               # Jump to VM console (dl-master, da-master, mds, aio, sensor)
show autostart             # Display VM auto-start configuration
set autostart <vm> <on|off>  # Configure VM auto-start
monitor                    # Monitor VM resources and system status
```

**Supported VMs:**
- `dl-master`: Data Lake master VM
- `da-master` or `dr-master`: Data Analytics master VM
- `mds`: Metadata Server VM
- `aio`: All-In-One Data Processor VM
- `sensor`: Sensor VM

### 8. Patch Management

```bash
show patch_history         # Display patch application history
set patches <patch_file>   # Apply patches/updates
set patch <patch_file>     # Alias for set patches
```

### 9. CLI Utilities

```bash
show cli                   # Show CLI command history
clear                     # Clear command history
help                      # Display help information
help <command>            # Show help for specific command
quit                      # Exit CLI
```

## Installation

### Requirements

- **Python**: 3.10 or higher
- **Operating System**: Linux (Ubuntu 16.04 / 20.04 / 22.04 / 24.04 LTS recommended)
- **Privileges**: sudo privileges for system configuration commands
- **Environment**: KVM host with OpenXDR components deployed (optional, but recommended)

### Installation Steps

#### Method 1: Install from Repository (Recommended)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/RickLee-kr/Stellar-appliance-cli.git
   cd "Stellar appliance cli"
   ```

2. **Create and activate virtual environment (recommended):**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install the package:**
   ```bash
   pip install -e .
   ```

#### Method 2: Direct Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/RickLee-kr/Stellar-appliance-cli.git
   cd "Stellar appliance cli"
   ```

2. **Install directly:**
   ```bash
   pip install -e .
   ```

#### Verification

After installation, verify the CLI is available:
```bash
which aella_cli
aella_cli --help  # If help option is available
```

The `aella_cli` command should be available in your PATH after installation.

## Usage

### Starting the CLI

Run the CLI:
```bash
aella_cli
```

You will see the welcome message and the CLI prompt:
```
Welcome to Starlight Appliance
Appliance> 
```

### Command Structure

The CLI uses the following command structure:

```
<command> <subcommand> [parameters]
```

### Main Commands

- **`show <item>`**: Display information
  - `show interface`, `show ntp`, `show acl`, `show version`, etc.
- **`set <item> <parameters>`**: Change configuration
  - `set interface`, `set ntp`, `set acl`, `set timezone`, etc.
- **`unset <item> <parameters>`**: Remove configuration
  - `unset interface`, `unset ntp`, `unset acl`
- **`start <service>`**: Start service
- **`restart <service>`**: Restart service
- **`shutdown <service>`**: Shutdown service
- **`console <vm>`**: Access VM console
- **`monitor`**: Monitor VM resources and system status
- **`clear`**: Clear command history
- **`help`**: Display help information
- **`quit`**: Exit CLI

### Getting Help

```bash
help                    # List all available commands
help <command>          # Show help for specific command (e.g., help show)
show <item> ?           # Show usage for specific item (e.g., show interface ?)
set <item> ?            # Show usage for set command (e.g., set interface ?)
```

### Usage Examples

#### Network Configuration

```bash
# Display all network interfaces
Appliance> show interface

# Configure IP address for an interface (IP/Mask required)
Appliance> set interface mgt ip 192.168.1.100/24 gateway 192.168.1.1 dns 8.8.8.8 8.8.4.4

# Set DNS servers for an interface
Appliance> set interface mgt dns 8.8.8.8 8.8.4.4

# Restart interface to apply changes
Appliance> set interface mgt restart

# Display DNS configuration
Appliance> show dns

# Display gateway information
Appliance> show gateway
```

#### NTP Configuration

```bash
# Display current NTP configuration
Appliance> show ntp

# Add NTP server
Appliance> set ntp pool.ntp.org

# Remove NTP server
Appliance> unset ntp pool.ntp.org
```

#### Firewall (ACL) Management

```bash
# Display current ACL rules
Appliance> show acl

# Initialize ACL policy (select mode + interface)
Appliance> set acl policy

# Allow SSH access from specific IP
Appliance> set acl 192.168.1.100 22 "Admin SSH"

# Allow ICMP ping from specific IP
Appliance> set acl 192.168.1.10 icmp "Ping"

# Apply staged rules
Appliance> set acl apply

# Remove ACL rule
Appliance> unset acl 192.168.1.100 22
```

#### System Information

```bash
# Display system version information
Appliance> show version

# Display hostname
Appliance> show hostname

# Display service status
Appliance> show service

# Display routing table
Appliance> show route

# Display timezone
Appliance> show timezone

# Display system time
Appliance> show time
```

#### System Configuration

```bash
# Set timezone
Appliance> set timezone Asia/Seoul

# Set system time
Appliance> set time 2026-01-15 14:30:00

# Set hostname
Appliance> set hostname my-appliance

# Change administrator password
Appliance> set password
```

#### VM Management

```bash
# Access VM console
Appliance> console dl-master
Appliance> console aio
Appliance> console sensor

# Display VM auto-start configuration
Appliance> show autostart

# Enable VM auto-start
Appliance> set autostart dl-master on

# Disable VM auto-start
Appliance> set autostart dl-master off

# Monitor VM resources and system status
Appliance> monitor
```

#### Patch Management

```bash
# Display patch history
Appliance> show patch_history

# Apply patch
Appliance> set patches /path/to/patch.tar.gz
```

### Tab Completion

The CLI supports tab completion for commands and parameters. Press `TAB` to auto-complete:
- Command names
- VM names (dl-master, da-master, aio, sensor, etc.)
- Interface names
- Other parameters

## Supported Installer Scripts

This CLI is compatible with the following installer scripts from the [OpenXDR KVM Installer](../OpenXDR%20KVM%20Installer/) repository:

- **`DP-Installer.sh`**: Data Processor installer (Ubuntu 16.04 / 20.04 / 22.04 / 24.04)
- **`AIO-Sensor-Installer.sh`**: AIO + Sensor integrated installer
- **`Sensor-Installer.sh`**: Standard Sensor installer
- **`6000-Sensor-Installer.sh`**: High-performance Sensor installer (m6000-style)

### Compatibility Features

The CLI can automatically:
- Recognize and manage network configurations set by installer scripts
- Detect and manage NTP settings configured by installer scripts
- Work with ifupdown-based network configuration (used by installers)
- Support both NAT and bridge network modes
- Manage VMs deployed by the installer scripts

## Important Notes

### Network Configuration

- **Interface Restart Required**: After changing network settings, you must restart the interface for changes to take effect:
  ```bash
  set interface <interface> restart
  ```
- **Configuration Files**: Network configuration is managed using ifupdown (`/etc/network/interfaces` and `/etc/network/interfaces.d/*.cfg`)
- **Netplan**: If netplan is installed, it should be disabled (installer scripts handle this automatically)

### NTP Configuration

- **Automatic Service Restart**: NTP service is automatically restarted when NTP configuration is changed
- **Multiple NTP Implementations**: The CLI automatically detects and supports:
  - ntpsec (default for installer scripts)
  - chrony
  - systemd-timesyncd
  - legacy ntp

### Firewall (ACL) Rules

- **Staged Application**: Rules are staged by `set acl` and applied only by `set acl apply`
- **Reset Apply**: `set acl apply --reset` rebuilds the chain from staging
- **Persistence**: To make rules persistent across reboots, save iptables rules:
  ```bash
  sudo iptables-save > /etc/iptables/rules.v4
  # Or for Ubuntu:
  sudo netfilter-persistent save
  ```
- **Default Policy**: Policy mode is set by `set acl policy` (whitelist/blacklist). No rules are active until you apply staging.
- **Local Interface IPs**: Local interface IPs (e.g., 127.0.0.1, 192.168.0.100, 192.168.122.1) are:
  - Always allowed regardless of ACL deny rules
  - Hidden from `show acl` output
  - Cannot be removed using `unset acl`
  - Traffic to local interface IPs cannot be blocked

### Privileges

- **sudo Required**: Some commands may require `sudo` privileges for system configuration
- **Root Access**: Network and system configuration changes typically require root or sudo access

### VM Console Access

- **Supported VMs**: Console access is available for:
  - `dl-master`: Data Lake master VM
  - `da-master` or `dr-master`: Data Analytics master VM
  - `mds`: Metadata Server VM
  - `aio`: All-In-One Data Processor VM
  - `sensor`: Sensor VM
- **Exit Console**: Press `Ctrl+]` or type `exit` to exit VM console and return to CLI

### Logging

- **Log Location**: CLI operations are logged to `/var/log/aella/`
- **Log Files**: Check log files for detailed operation history and troubleshooting

## File Structure

```
Stellar appliance cli/
├── appliance_cli.py       # Main CLI application
├── setup.py              # Package setup configuration
└── README.md             # This file
```

### Configuration Files Managed by CLI

The CLI manages the following system configuration files:

**Network Configuration:**
- `/etc/network/interfaces`: Main network interface configuration
- `/etc/network/interfaces.d/*.cfg`: Per-interface configuration files

**NTP Configuration:**
- `/etc/ntpsec/ntp.conf`: ntpsec configuration (default for installer scripts)
- `/etc/chrony/chrony.conf`: chrony configuration
- `/etc/systemd/timesyncd.conf`: systemd-timesyncd configuration
- `/etc/ntp.conf`: legacy ntp configuration

**Firewall (iptables):**
- iptables INPUT chain rules (runtime)
- `/etc/iptables/rules.v4`: Persistent iptables rules (manual save required)

**Logs:**
- `/var/log/aella/`: CLI operation logs

## Troubleshooting

### Common Issues

1. **Command not found: aella_cli**
   ```bash
   # Verify installation
   pip show dp-cli
   
   # Reinstall if needed
   pip install -e .
   
   # Check PATH
   which aella_cli
   ```

2. **Permission denied errors**
   - Ensure you have sudo privileges
   - Some commands require root access
   - Check file permissions for configuration files

3. **Network changes not taking effect**
   - Restart the interface after configuration:
     ```bash
     set interface <interface> restart
     ```
   - Verify ifupdown is active (not netplan)
   - Check network service status: `systemctl status networking`

4. **NTP service not working**
   - Check which NTP service is active:
     ```bash
     systemctl status ntpsec
     systemctl status chrony
     systemctl status systemd-timesyncd
     ```
   - Verify NTP configuration: `show ntp`
   - Check NTP service logs

5. **ACL rules not persisting after reboot**
   - Save iptables rules manually:
     ```bash
     sudo iptables-save > /etc/iptables/rules.v4
     # Or for Ubuntu:
     sudo netfilter-persistent save
     ```
   - Install netfilter-persistent if not available:
     ```bash
     sudo apt install netfilter-persistent
     ```

6. **VM console not accessible**
   - Verify VM is running: `show service`
   - Check libvirt connection: `virsh list --all`
   - Ensure VM name matches (dl-master, da-master, aio, sensor, etc.)

### Getting Help

- Use the built-in help: `help` or `help <command>`
- Check command usage: `show <item> ?` or `set <item> ?`
- Review log files in `/var/log/aella/`
- Check system logs: `journalctl -xe`

## License

Copyright (c) 2026, Stellar Cyber Inc.

## Contributing

Please submit issue reports or feature suggestions through GitHub Issues.

## Related Projects

- [OpenXDR KVM Installer](../OpenXDR%20KVM%20Installer/): KVM host installation scripts for deploying OpenXDR components
