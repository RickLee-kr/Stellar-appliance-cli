# Stellar Appliance CLI

A command-line interface (CLI) tool for Stellar Cyber Appliance. It allows you to manage network settings, NTP configuration, firewall rules, and more on KVM hosts running OpenXDR Data Processor and Sensor components.

## Table of Contents

- Overview
- Installation
- Usage
- Command Summary
- ACL Workflow
- Supported Installer Scripts
- Important Notes
- File Structure
- Troubleshooting
- License
- Contributing
- Related Projects

## Overview

The Stellar Appliance CLI provides a unified interface for managing KVM hosts deployed using the OpenXDR KVM Installer scripts. It automatically recognizes and manages configurations set by the installer scripts.

Key areas covered:
- Network configuration (IP/Mask required, DNS on `mgt` only)
- NTP configuration (ntpsec, chrony, systemd-timesyncd, legacy ntp)
- ACL management with staged rules and ICMP support
- System information/configuration and service control
- VM console and autostart control, patch management

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

### Tab Completion

The CLI supports tab completion for commands and parameters. Press `TAB` to auto-complete:
- Command names
- VM names (dl-master, da-master, aio, sensor, etc.)
- Interface names
- Other parameters

## Command Summary

### Network
```bash
show interface
set interface <interface> ip <IP/Mask> [gateway <IP>]
set interface <interface> gateway <IP>
set interface mgt dns <dns1> [dns2 ...]
set interface <interface> restart
unset interface <interface> <ip|gateway|restart>
show dns
set dns <interface> <dns1> [dns2 ...]
show gateway
```

### NTP
```bash
show ntp
set ntp <server>
unset ntp <server>
```

### ACL
```bash
show acl
set acl policy
set acl <IP/network> <port|icmp|ping|all> [description]
set acl apply [--reset]
unset acl <IP/network> <port|icmp|ping> [...] | all
```

### System and Services
```bash
show version|hostname|service|timezone|time|route
set timezone <timezone>
set time <YYYY-MM-DD HH:MM:SS>
set hostname <hostname>
set password
start <service>
restart <service>
shutdown <service>
```

### VM and Patch
```bash
console <vm>
show autostart
set autostart <vm> [enable|disable]
monitor
show patch_history
set patches <patch_file>
```

## ACL Workflow

1. Initialize policy and target interface:
   `set acl policy`
2. Stage rules (ports, `icmp`/`ping`, or `all`):
   `set acl <IP/network> <port|icmp|ping|all> [description]`
3. Apply staged rules:
   `set acl apply` (or `set acl apply --reset`)
4. Review:
   `show acl`
5. Remove rules:
   `unset acl <IP/network> <port|icmp|ping> [...] | all`

Notes:
- Rule action follows policy mode: whitelist = allow, blacklist = deny
- Local interface IPs are always allowed and cannot be blocked

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

- [OpenXDR KVM Installer](https://kvm.xdr.ooo): KVM host installation scripts for deploying OpenXDR components
