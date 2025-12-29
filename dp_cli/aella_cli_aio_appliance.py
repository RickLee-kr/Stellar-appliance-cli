#!/usr/bin/env python3
"""
Copyright (c) 2021, Stellar Cyber Inc.

Appliance Command Line Interface (CLI)

Date: 2021-01-21

"""

import datetime
import getpass
import json
import os
import os.path
import re
import sys
import cmd

try:
    import readline
except Exception:
    readline = None

import socket
import signal
import subprocess
import struct
import hashlib
import pyfiglet
import termcolor
import logging
import logging.handlers
import functools

from .utils import disk_encrypt
from .utils.log import LOG, log_cmd
from .utils.constant import ALL_TIMEZONES

META_USER = "AellaMeta"

META_TOKEN = "WroTQfm/W6x10"

PATCH_DIR = "/home/stellar/hotfix"
PATCH_LOG_DIR = "{}/logs".format(PATCH_DIR)
PATCH_HISTORY = "{}/hotfix-history".format(PATCH_DIR)


# Implemented the check_output to support python 2.6
def check_output(*popenargs, **kwargs):
    process = subprocess.Popen(stdout=subprocess.PIPE, *popenargs, **kwargs)
    output, unused_err = process.communicate().decode()
    retcode = process.poll()
    if retcode:
        cmd = kwargs.get("args")
        if cmd is None:
            cmd = popenargs[0]
        raise subprocess.CalledProcessError(retcode, cmd, output=output)
    return output


class AellaCli(cmd.Cmd, object):
    """Aella Data Appliance CLI"""
    intro = '\nWelcome to Starlight Appliance\n'
    prompt = 'Appliance> '

    def __init__(self):
        cmd.Cmd.__init__(self)

        # Enable TAB completion (readline)
        if readline:
            try:
                readline.parse_and_bind('tab: complete')
            except Exception:
                pass
            # Treat '-' as part of a word so 'dl-master' can be completed
            try:
                readline.set_completer_delims(' \t\n')
            except Exception:
                pass
        self.deu = disk_encrypt.DiskEncryptUtil(logger=LOG)

        # Root command help
        self.root_command_help = {
            'console': 'Jump to mds2, dl-master, da-master(aka dr-master), or mds console',
            'show': 'Display Component Information',
            'set': 'Configure Component Parameters ',
            'unset': 'Unset Configuration',
            'shutdown': 'Shutdown System Or Service',
            'start': 'Start System Or Service',
            'restart': 'Restart System Or Service',
            'disk_encrypt': 'Execute operations of disk encryption',
            'clear': 'Clear History',
            'monitor': 'Monitor VM resources and system health',
            'health': 'Check system health status',
            'quit': 'Exit CLI',
            'help': 'Display Help Information  ',
        }

        # Show command help
        self.show_command_help = {
            'version': 'Show System Information',
            'hostname': 'Show Hostname',
            'service': 'Show Service Information',
            'interface': 'Show Interface Information',
            'timezone': 'Show Timezone Information',
            'time': 'Show System Time',
            'ntp': 'Show NTP Information',
            'gateway': 'Show Default Gateway Information',
            'dns': 'Show DNS Server Information',
            'route': 'Show Routing Table', 
            'cli': 'Show CLI History',
            'patch_history': 'Show the History of Patches Applied',
            'autostart': 'Show VM Auto Start Configuration',
        }

        # Show command callback
        self.show_command_callback = {
            'version': self.show_version,
            'hostname': self.show_hostname,
            'service': self.show_service,
            'interface': self.show_interface_callback,
            'timezone': self.show_tz_callback,
            'time': self.show_time_callback,
            'ntp': self.show_ntp_callback,
            'gateway': self.show_gateway_callback,
            'dns': self.show_dns_callback,
            'route': self.show_route_callback,
            'cli': self.show_cli_callback,
            'patch_history': self.show_patch_history_callback,
            'autostart': self.show_autostart_callback,
        }

        # Set command help
        self.set_command_help = {
            'password': 'Configure Admin Password',
            'timezone': 'Configure System Timezone',
            'time': 'Configure System Time',
            'ntp': 'Configure NTP Server',
            'interface': 'Configure Interface Parameters',
            'hostname': 'Configure Host Name',
            'patches': 'Apply patches/update',
            'autostart': 'Configure VM Auto Start',
        }

        # Set command callback
        self.set_command_callback = {
            'password': self.set_password_callback,
            'timezone': self.set_tz_callback,
            'time': self.set_time_callback,
            'ntp': self.set_ntp_callback,
            'interface': self.set_interface_callback,
            'hostname': self.set_hostname_callback,
            'patches': self.set_patches_callback,
            'patch': self.set_patches_callback,
            'autostart': self.set_autostart_callback,
        }

        self.unset_command_help = {
            'ntp': 'Unset NTP Server',
            'interface': 'Unset interface configuration'
        }

        self.unset_command_callback = {
            'ntp': self.unset_ntp_callback,
            'interface': self.unset_interface_callback
        }

        # Dynamically build start command help and callback from virsh list
        self.start_command_help = {}
        self.start_command_callback = {}
        vm_list = self.get_vm_list()
        for vm in vm_list:
            self.start_command_help[vm] = 'Start {}'.format(vm)
            self.start_command_callback[vm] = self._create_vm_start_callback(vm)

        # Dynamically build restart command help and callback from virsh list
        self.restart_command_help = {'system': 'Reboot appliance'}
        self.restart_command_callback = {'system': self.restart_system_callback}
        vm_list = self.get_vm_list()
        for vm in vm_list:
            self.restart_command_help[vm] = 'Restart {}'.format(vm)
            self.restart_command_callback[vm] = self._create_vm_restart_callback(vm)

        # Dynamically build shutdown command help and callback from virsh list
        self.shutdown_command_help = {'system': 'Shutdown appliance'}
        self.shutdown_command_callback = {'system': self.shutdown_system_callback}
        vm_list = self.get_vm_list()
        for vm in vm_list:
            self.shutdown_command_help[vm] = 'Shutdown {}'.format(vm)
            self.shutdown_command_callback[vm] = self._create_vm_shutdown_callback(vm)

        # Dynamically build console command help and callback from virsh list
        self.console_command_help = {}
        self.console_command_callback = {}
        vm_list = self.get_vm_list()
        for vm in vm_list:
            self.console_command_help[vm] = 'Goto {} console'.format(vm)
            self.console_command_callback[vm] = self._create_vm_console_callback(vm)

        self.clear_command_help = {
            'cli': 'Clear CLI history',
        }

        self.clear_command_callback = {
            'cli': self.clear_cli_callback,
        }

        # Monitor command
        self.monitor_command_help = {
            'vm': 'Monitor VM resource usage',
        }

        self.monitor_command_callback = {
            'vm': self.monitor_vm_callback,
        }

        # Health command
        self.health_command_help = {
            'check': 'Check system health status',
        }

        self.health_command_callback = {
            'check': self.health_check_callback,
        }

        # Shell command
        self.shell_command = [
            'ping', 'tcpdump', 'traceroute', 'ifconfig', 'iptables', 'dmesg', 'ip', 'dig'
        ]
        self.shell_pass = '0238b57cd42b4aa6b85991ea28702133'

        # Disk Encryption
        self.disk_encrypt_command_help = {
            'enable': 'Enable disk encryption, sets the initial passphrase and restart vm.',
            'disable': 'Disable disk encryption and restart dl-master/aio vm.',
            'open': 'Open encrypte  d disk',
            'close': 'Close encrypted disk',
            'add_key': 'Add a new passphrase.',
            'remove_key': 'Removes the supplied passphrase.',
            'change_key': 'Changes an existing passphrase.',
            'backup_header': 'Stores a binary backup of the LUKS header and keyslot area.',
            'restore_header': 'Restores a binary backup of the LUKS header and keyslot area from the specified file.',
            'info': 'Dump the header information of device',
        }

        self.disk_encrypt_command_callback = {
            'enable': self._create_disk_encrypt_callback(self._on_disk_encrypt_enable_callback),
            'disable': self._create_disk_encrypt_callback(self._on_disk_encrypt_disable_callback),
            'open': self._create_disk_encrypt_callback(self._on_disk_encrypt_open_callback),
            'close': self._create_disk_encrypt_callback(self._on_disk_encrypt_close_callback),
            'add_key': self._create_disk_encrypt_callback(self._on_disk_encrypt_add_key_callback),
            'remove_key': self._create_disk_encrypt_callback(self._on_disk_encrypt_remove_key_callback),
            'change_key': self._create_disk_encrypt_callback(self._on_disk_encrypt_change_key_callback),
            'backup_header': self._create_disk_encrypt_callback(self._on_disk_encrypt_backup_header_callback),
            'restore_header': self._create_disk_encrypt_callback(self._on_disk_encrypt_restore_header_callback),
            'info': self._create_disk_encrypt_callback(self._on_disk_encrypt_info_callback),
        }

    # Main loop
    def cmdloop(self, intro=None):
        print(self.intro)
        while True:
            try:
                super(AellaCli, self).cmdloop(intro="")
                self.postloop()
                break
            except KeyboardInterrupt:
                print("^C")

    @staticmethod
    def get_da_name():
        try:
            retcode = subprocess.call('virsh dominfo da-master > /dev/null 2>&1', shell=True)
            if retcode:
                return 'dr-master'
            else:
                return 'da-master'
        except Exception:
            return 'dr-master'

    @staticmethod
    def get_vm_list():
        """Get list of all VMs from virsh list --all"""
        vm_list = []
        try:
            cmd = "virsh list --all --name 2>/dev/null"
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = proc.communicate()
            if out:
                vm_list = [vm.strip() for vm in out.decode('utf-8', errors='ignore').split('\n') if vm.strip()]
        except Exception:
            pass
        return vm_list

    def completenames(self, text, line, begidx, endidx):
        if not text:
            completions = self.root_command_help.keys()
        else:
            completions = [f for f in self.root_command_help.keys() if f.startswith(text)]
        return completions

    def complete_console(self, text, line, begidx, endidx):
        # console <vmname> completion
        keys = list(self.console_command_help.keys())
        if not text:
            return keys
        return [k for k in keys if k.startswith(text)]

    def is_password_valid(self):
        passcode = getpass.getpass('')
        return passcode and hashlib.md5(passcode.encode('utf-8')).hexdigest() == self.shell_pass

    @staticmethod
    def _on_nested_command(line, help_meta, callback_meta):
        key = ''
        param = ''
        if line:
            key = line.split()[0]
            param = line.split()[1:]
        if key and key in callback_meta:
            callback = callback_meta.get(key)
            if callback:
                callback(key, param)
        elif not key or key == '?' or key == 'help':
            print('')
            for cmd in sorted(help_meta.keys()):
                print('{:15} {}'.format(cmd, help_meta[cmd]))
            print('')
        else:
            partial_matched = False
            for full_key in help_meta.keys():
                if full_key.startswith(key):
                    partial_matched = True
                    key = full_key
                    break
            if partial_matched:
                callback = callback_meta.get(key)
                if callback:
                    callback(key, param)
            else:
                print("*** Unknown syntax: {}".format(line))

    # Help command
    def do_help(self, line):
        print('')
        for cmd in sorted(self.root_command_help.keys()):
            print('{0:15} {1}'.format(cmd, self.root_command_help[cmd]))
        print('')

    # Shell command
    @log_cmd
    def do_shell(self, line):
        """Shell command"""
        key = ''
        passcode = ''
        if line:
            key = line.split()[0]

        if not key:
            if self.is_password_valid():
                subprocess.call("/usr/bin/sudo bash", shell=True)
        elif key in self.shell_command:
            # Prevent displaying aella_cli content
            if line.find('cli') >= 0:
                return
            elif key == 'tcpdump' or key == 'iptables':
                line = 'sudo ' + line
            else:
                line = line

            tokens = line.split()
            try:
                subprocess.call(tokens, shell=False)
            except Exception as e:
                print("Command failed {}".format(e))

    @staticmethod
    def show_cmd_default_callback(key, param):
        if key:
            return None 

    # Restart command
    def complete_restart(self, text, line, begidx, endidx):
        if not text:
            completions = self.restart_command_help.keys()
        else:
            completions = [f for f in self.restart_command_help.keys() if f.startswith(text)]
        return completions

    @log_cmd
    def do_restart(self, line):
        """ Restart command """
        return self._on_nested_command(line, self.restart_command_help, self.restart_command_callback)

    def restart_system_callback(self, key, param):
        """Restart System"""
        ans = ""
        while ans != "Y" and ans != "n" and ans != "y" and ans != "N":
            ans = input('Restart Appliance, are you sure? [Y/n]: ')
        if ans == "Y" or ans == "y":
            print('Restarting...')
            self.shell_cmd_exec('sync; reboot')
        else:
            print('Restarting operation aborted.')

    def _create_vm_start_callback(self, vm_name):
        """Create a callback function for starting a VM"""
        def callback(key, param):
            # Special handling for dl-master
            if vm_name == 'dl-master':
                if not self.deu.ensure_open_encrypted_disk():
                    self.deu.print_log("Failed to prepare stellar data disk", level=logging.ERROR)
                    return
            self.shell_cmd_exec('virsh start {}'.format(vm_name))
        return callback

    def _create_vm_restart_callback(self, vm_name):
        """Create a callback function for restarting a VM"""
        def callback(key, param):
            self.shell_cmd_exec('virsh reboot {}'.format(vm_name))
        return callback

    def _create_vm_shutdown_callback(self, vm_name):
        """Create a callback function for shutting down a VM"""
        def callback(key, param):
            # Special handling for dl-master
            if vm_name == 'dl-master':
                for vm in self.deu.get_vm_names(services=("dl-master",)):
                    if not self.deu.shutdown_vm(vm, destroy=False):
                        print("\nWARNING: Failed to shutdown dl-master gracefully and will kill dl-master.")
                        if not self.deu.double_confirm() or not self.deu.destroy_vm(vm):
                            return
                self.deu.ensure_close_encrypted_disk()
            else:
                self.shell_cmd_exec('virsh shutdown {}'.format(vm_name))
        return callback

    def _create_vm_console_callback(self, vm_name):
        """Create a callback function for console access to a VM"""
        def callback(key, param):
            subprocess.call('virsh console --force {}'.format(vm_name), shell=True)
        return callback

    def complete_start(self, text, line, begidx, endidx):
        if not text:
            completions = self.start_command_help.keys()
        else:
            completions = [f for f in self.start_command_help.keys() if f.startswith(text)]
        return completions

    @log_cmd
    def do_start(self, line):
        """ Start command """
        return self._on_nested_command(line, self.start_command_help, self.start_command_callback)


    def shutdown_system_callback(self, key, param):
        ans = ""
        while ans != "Y" and ans != "n" and ans != "y" and ans != "N":
            ans = input('Shutdown Appliance, are you sure? [Y/n]: ')
        if ans == "Y" or ans == "y":
            print('Shutting down...')
            self.shell_cmd_exec('shutdown -h now')
        else:
            print('Shutdown operation aborted.')


    # Quit command
    @log_cmd
    def do_quit(self, line):
        """ Quit"""
        return True

    def emptyline(self):
        return

    # Show command
    @log_cmd
    def do_show(self, line):
        """ Show command """
        return self._on_nested_command(line, self.show_command_help, self.show_command_callback)

    # Clear command
    @log_cmd
    def do_clear(self, line):
        """ Show command """
        return self._on_nested_command(line, self.clear_command_help, self.clear_command_callback)

    # Monitor command
    @log_cmd
    def do_monitor(self, line):
        """ Monitor command """
        return self._on_nested_command(line, self.monitor_command_help, self.monitor_command_callback)

    # Health command
    @log_cmd
    def do_health(self, line):
        """ Health command """
        return self._on_nested_command(line, self.health_command_help, self.health_command_callback)

    # Console command
    @log_cmd
    def do_console(self, line):
        """ Console command """
        return self._on_nested_command(line, self.console_command_help, self.console_command_callback)

    # Shutdown command
    def complete_shutdown(self, text, line, begidx, endidx):
        if not text:
            completions = self.shutdown_command_help.keys()
        else:
            completions = [f for f in self.shutdown_command_help.keys() if f.startswith(text)]
        return completions

    @log_cmd
    def do_shutdown(self, line):
        """Shutdown command """
        return self._on_nested_command(line, self.shutdown_command_help, self.shutdown_command_callback)

    def complete_show(self, text, line, begidx, endidx):
        if not text:
            completions = self.show_command_help.keys()
        else:
            completions = [f for f in self.show_command_help.keys() if f.startswith(text)]
        return completions

    # Need to use timedatectl to get the timezone for both Ubuntu 16.04 and 24.04
    def show_tz_callback(self, key, param):
        try:
            result = subprocess.check_output(["timedatectl"])
            if sys.version_info[0] >= 3:  # Python 3
                result = result.decode("utf-8")

            for line in result.splitlines():
                if "Time zone" in line:
                    print(line.split(":")[1].split()[0].strip())
        except subprocess.CalledProcessError:
            print("Failed to retrieve timezone using timedatectl")

    def show_time_callback(self, key, param):
        self.shell_cmd_exec('date \"+%a %Y-%m-%d %H:%M:%S %Z\"')

    def show_ntp_callback(self, key, param):
        status = 0
        output = None

        # kt_DP-installer-v1.4.sh STEP06 uses NTPsec: /etc/ntpsec/ntp.conf
        ntp_conf = "/etc/ntpsec/ntp.conf"
        if not os.path.exists(ntp_conf):
            ntp_conf = "/etc/ntp.conf"  # fallback


        try:
            # 1) configured servers from config
            cmd = "cat {} 2>/dev/null".format(ntp_conf)
            check_proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
            result = check_proc.communicate()[0].decode()
            result = result.split("\n")

            server_list = []
            for line in result:
                pools = re.findall(r"^pool\s+(\S+)", line)
                servers = re.findall(r"^server\s+(\S+)", line)
                if pools:
                    server_list.extend(pools)
                if servers:
                    server_list.extend(servers)

            output = "\n"
            output += "[config] {}\n".format(ntp_conf)
            output += "\n".join(server_list) + "\n"

            # 2) runtime status (align with installer validation)
            output += "\n[service]\n"
            try:
                out = subprocess.check_output(["systemctl", "is-active", "ntpsec"]).decode("utf-8").strip()
            except Exception:
                out = "unknown"
            output += "ntpsec: {}\n".format(out)

            output += "\n[ntpq -p]\n"
            try:
                out = subprocess.check_output(["ntpq", "-p"]).decode("utf-8").strip()
            except Exception:
                out = "(failed)"
            output += out + "\n"

            print(output)
            return status, output

        except Exception as e:
            print("Failed to get ntp servers: {}".format(e))
            return 1, None
    

    def show_dns_callback(self, key, param):
        status = 0
        output = None
        cmd = "cat /etc/resolv.conf"
        try:
            check_proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
            result = check_proc.communicate()[0]
            result = result.decode()
            tokens = re.findall(".*\s+(\d+\.\d+\.\d+\.\d+).*", result)
            output = "\n"
            output += "\n".join(tokens)
            output += "\n"
        except Exception as e:
            print("Failed to get dns servers: ".format(e))
        print(output)


    def is_sensor_host_mode(self):
        """Detect whether this host is a Sensor KVM host (mds/mds2, br-data, etc.)."""
        try:
            if os.path.exists('/sys/class/net/br-data'):
                return True
            cmd = "virsh list --all --name 2>/dev/null | egrep -w 'mds|mds2' || true"
            out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode('utf-8', errors='ignore').strip()
            if out:
                return True
        except Exception:
            pass
        return False

    def list_host_nics(self):
        """Return a filtered list of host NIC/bridge names."""
        nics = []
        try:
            for i in os.listdir('/sys/class/net/'):
                if i == 'lo':
                    continue
                # Filter obvious virtual/ephemeral interfaces; keep physical + intentional bridges
                if re.match(r'^(vnet|tap|tun|docker|cni|flannel|kube|wg|zt|tailscale)', i):
                    continue
                nics.append(i)
        except Exception:
            pass
        return sorted(set(nics))

    def show_gateway_sensor(self):
        """Show gateway info for Sensor host using the main routing table."""
        try:
            cmd = "ip route show default"
            p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            out, err = p.communicate()
            if out:
                print('\nHost default gateway(s):')
                for line in out.decode('utf-8', errors='ignore').splitlines():
                    print('  ' + line)
                print('')
            else:
                print('\nHost default gateway is not configured or applied\n')
        except Exception as e:
            print('Failed to get host gateway: {}'.format(e))

    def show_interface_sensor(self, param):
        """Show host NIC details for Sensor host."""
        if len(param) == 0:
            # concise inventory first
            self.shell_cmd_exec('ip -br addr show')
            print('')
            return

        iface = param[0].rstrip('?')
        if iface == '?' or param[0].endswith('?'):
            print('\n<Interface Name>  Specify an existing host interface/bridge name\n')
            return

        if not self.is_device_exist(iface):
            return

        self.shell_cmd_exec('sudo ifconfig {0} 2>/dev/null'.format(iface))
        cmd = 'ip link show {0} | grep -oP "\\s+state\\s+\\K\\w+" 2>/dev/null'.format(iface)
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        out, _ = p.communicate()
        if out:
            state = out.decode('utf-8', errors='ignore').rstrip()
            print('Link state: {}\n'.format(state))
        self.shell_cmd_exec('ip link show {0} 2>/dev/null'.format(iface))
        # ethtool may fail for some virtual/bridge interfaces; ignore errors
        self.shell_cmd_exec('ethtool {0} 2>/dev/null'.format(iface))
        self.shell_cmd_exec('ethtool -i {0} 2>/dev/null | grep -E "^driver|^version|^firmware-version|^bus-info"'.format(iface))

    def set_interface_sensor(self, param):
        """Configure host interface for Sensor host (uses /etc/network/interfaces)."""
        if not param or len(param) < 1:
            print('\n<Interface Name>  Specify an existing host interface/bridge name\n')
            return

        interface = param[0].rstrip('?')
        if param[0].endswith('?') or interface == '?':
            print('\n<Interface Name>  Specify an existing host interface/bridge name\n')
            return

        if not self.is_device_exist(interface):
            return

        if len(param) == 1 or (len(param) == 2 and param[1] == '?') or (len(param) == 2 and param[1].endswith('?')):
            print('\nip <IP Address/Netmask>   Specify interface IP address and netmask')
            print('gateway <IP Address>      Specify default gateway IP address')
            print('dns <IP Address> [...]    Specify DNS server IP address(es) separated by space')
            print('restart                   Restart network interface\n')
            return

        option = param[1]
        if option not in ['ip', 'gateway', 'dns', 'restart']:
            print('Invalid option: Available options are "ip", "gateway", "dns" and "restart"\n')
            return

        # Reuse existing validation and implementation by calling set_interface_callback2
        # which edits /etc/network/interfaces. For restart, keep existing restart logic.
        if option == 'restart':
            print('Restarting network interface. You need to use new IP address to reconnect...\n')
            self.restart_new_network_manager(interface)
            return

        # Minimal validation (use existing helper)
        if option == 'ip':
            if len(param) < 3 or not self.valid_ipv4_address(param[2]):
                print('\n<IP Address/Netmask>   Specify interface IP address and netmask\n')
                return
            if '/' not in param[2]:
                print('Please specify network mask: {0}\n'.format(param[2]))
                return
        if option == 'gateway':
            if len(param) < 3 or not self.valid_ipv4_address(param[2]) or '/' in param[2]:
                print('\n<IP Address>      Specify default gateway IP address\n')
                return
        if option == 'dns':
            if len(param) < 3:
                print('\n<IP Address> [...]    Specify DNS server IP address(es) separated by space\n')
                return
            for d in param[2:]:
                if not self.valid_ipv4_address(d):
                    print('Invalid DNS server IP address format: {0}\n'.format(d))
                    return

        # Delegate to the existing interface-file editor
        self.set_interface_callback2([interface] + param[1:])

    def unset_interface_sensor(self, param):
        """Unset host interface configuration for Sensor host (uses /etc/network/interfaces)."""
        if not param or len(param) < 1:
            print('\n<Interface Name>  Specify an existing host interface/bridge name\n')
            return

        interface = param[0].rstrip('?')
        if param[0].endswith('?') or interface == '?':
            print('\n<Interface Name>  Specify an existing host interface/bridge name\n')
            return

        if not self.is_device_exist(interface):
            return

        if len(param) == 1 or (len(param) == 2 and param[1] == '?') or (len(param) == 2 and param[1].endswith('?')):
            print('\nip         Unset the IP address on the interface {}'.format(interface))
            print('gateway    Unset the default gateway on the interface {}'.format(interface))
            print('restart    Restart network interface\n')
            return

        option = param[1]
        if option not in ['ip', 'gateway', 'restart']:
            print('Invalid option: Available options are "ip", "gateway" and "restart"\n')
            return

        if option == 'restart':
            print('Restarting network interface. You need to use new IP address to reconnect...\n')
            self.restart_new_network_manager(interface)
            return

        # Use existing unset logic but without DP-only restrictions by temporarily bypassing checks
        # Implement a small local edit on /etc/network/interfaces
        try:
            conf_path = '/etc/network/interfaces'
            if not os.path.exists(conf_path):
                print('Cannot find {}'.format(conf_path))
                return
            with open(conf_path, 'r') as f:
                lines = f.readlines()

            out = []
            in_block = False
            for line in lines:
                if re.match(r'^\s*iface\s+{}\s+'.format(re.escape(interface)), line):
                    in_block = True
                    out.append(line)
                    continue
                if in_block:
                    if re.match(r'^\s*iface\s+\S+\s+', line) or re.match(r'^\s*auto\s+\S+', line):
                        in_block = False
                    if in_block:
                        if option == 'ip' and re.match(r'^\s*address\s+', line):
                            continue
                        if option == 'ip' and re.match(r'^\s*netmask\s+', line):
                            continue
                        if option == 'ip' and re.match(r'^\s*(gateway|dns-nameservers)\s+', line):
                            # keep gateway/dns unless explicitly removing gateway
                            out.append(line)
                            continue
                        if option == 'gateway' and re.match(r'^\s*gateway\s+', line):
                            continue
                        out.append(line)
                        continue
                out.append(line)

            with open(conf_path, 'w') as f:
                f.writelines(out)

            print("Run 'unset interface {0} restart' command to apply the changes.\n".format(interface))
        except Exception as e:
            print('Failed to unset interface configuration: {}'.format(e))

    def show_gateway_callback(self, key, param):
        if self.is_sensor_host_mode():
            self.show_gateway_sensor()
            return

        def check_default_gw(cmd):
            try:
                p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                res = p.communicate() 
                if res[0]:
                    m = re.match("default\s+via\s+(\d+\.\d+\.\d+\.\d+)\s+dev\s+(\w+)", res[0].decode('utf-8').rstrip())
                    return m
            except Exception as e:
                print("Failed to get gateway: ".format(e))

        # find mgt network default gateway
        cmd = "ip route show table 1 | grep default"
        result = check_default_gw(cmd)
        if result:
            print('\nManagement network gateway {} via {} interface'.format(result.group(1), result.group(2)))
        else:
            print('\nManagement network gateway is not configured or applied')

        # find data network gateway
        cmd = "ip route show table 2 | grep default"
        result = check_default_gw(cmd)
        if result:
            print('Data network gateway {} via {} interface\n'.format(result.group(1), result.group(2)))
        else:
            print('Data network gateway is NOT configured or applied !!!\n')

    def show_service(self, key, param):
        if key:
            self.shell_cmd_exec('sudo virsh list --all')

    def show_autostart_callback(self, key, param):
        """Show VM auto start configuration"""
        vm_list = self.get_vm_list()
        if not vm_list:
            print('\nNo VMs found.\n')
            return

        print('\nVM Auto Start Configuration:')
        print('-' * 50)
        for vm in sorted(vm_list):
            try:
                cmd = "virsh dominfo {} 2>/dev/null | grep -i 'autostart'".format(vm)
                proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, err = proc.communicate()
                if out and 'enabled' in out.decode('utf-8', errors='ignore').lower():
                    status = 'enabled'
                else:
                    status = 'disabled'
                print('  {:<20} {}'.format(vm, status))
            except Exception:
                print('  {:<20} unknown'.format(vm))
        print('')

    def show_interface_callback(self, key, param):
        if self.is_sensor_host_mode():
            self.show_interface_sensor(param)
            return

        if key:
            if len(param) == 0:
                interface_list = os.listdir('/sys/class/net/')
                for i in interface_list:
                    if ('en' in i) or ('eth' in i) or ('br0-aio' in i) or ('mgt' in i) or ('mgmt' in i) or ('xmgt' in i) \
                        or ('data1g' in i) or ('data10g' in i) or ('cltr0' in i):
                        self.shell_cmd_exec('sudo ifconfig {0} 2>/dev/null'.format(i))
            elif len(param) <= 2:
                #if len(param) == 1 and (param[0].endswith('mgt?') or param[0].endswith('data1g?') or param[0].endswith('data10g?')):
                if len(param) == 1 and re.match('mgt[?]|data1[0]?g[?]|cltr0[?]', param[0]):
                     print('\nHit [Enter]\n')
                     return
                #elif len(param) == 1 and (param[0] == '?' or not (param[0] == 'mgt' or param[0] == 'data1g' or param[0] == 'data10g')):
                elif len(param) == 1 and (param[0] == '?' or not re.match('mgt|data1[0]?g|cltr0', param[0])):
                    print('\n<Interface Name>  Specify a supported interface name (mgt, data1g, data10g, cltr0)')
                    print('Hit [Enter]\n')
                    return
                elif len(param) == 1 and not self.is_device_exist(param[0]):
                    return
                #elif len(param) == 1 and (param[0] == 'mgt' or param[0] == 'data1g' or param[0] == 'data10g'):
                elif len(param) == 1 and re.match('mgt|data1[0]?g|cltr0', param[0]):
                    self.shell_cmd_exec('sudo ifconfig {0} 2>/dev/null'.format(param[0]))
                    cmd = 'ip link show {0} | grep -oP "\s+state\s+\K\w+" 2>/dev/null'.format(param[0])
                    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                    res = p.communicate()
                    if res[0]:
                        state = res[0].decode('utf-8').rstrip()
                        print('Link state: {}\n'.format(state))
                    if param[0] == 'cltr0':
                        self.shell_cmd_exec('ip link show {0}'.format(param[0]))
                    self.shell_cmd_exec('ethtool {}'.format(param[0]))
                    self.shell_cmd_exec('ethtool -i {} | grep -E "^driver|^version|^firmware-version|^bus-info"'.format(param[0]))
                #elif len(param) == 2 and (param[0] == 'mgt' or param[0] == 'data1g' or param[0] == 'data10g') and param[1] == '?' :
                elif len(param) == 2 and re.match('mgt|data1[0]?g|cltr0', param[0]) and param[1] == '?' :
                     print('\nHit [Enter]\n')
                     return

    def show_route_callback(self, key, param):
        # Show all routing tables
        # - main : the default host routing table
        # -    1 : the management network routing table
        # -    2 : the data network routing table
        try:
            cmd_table_main = 'ip route show table main'
            cmd_table_1 = 'ip route show table 1'
            cmd_table_2 = 'ip route show table 2'

            p = subprocess.Popen(cmd_table_main, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            res = p.communicate()
            if res[0]:
                print('\n' + '-' * 87)
                print('Main routing table')
                print('-' * 87)
                for i in res:
                    print(i.decode('utf-8').rstrip())
            else:
                print('-' * 87)
                print('Main routing table')
                print('-' * 87)
                print('N/A')

            p = subprocess.Popen(cmd_table_1, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            res = p.communicate()
            if res[0]:
                print('-' * 87)
                print('Management network routing table (table 1)')
                print('-' * 87)
                for i in res:
                    print(i.decode('utf-8').rstrip())
            else:
                print('-' * 87)
                print('Main routing table')
                print('-' * 87)
                print('N/A')

            p = subprocess.Popen(cmd_table_2, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            res = p.communicate()
            if res[0]:
                print('-' * 87)
                print('Data network routing table (table 2)')
                print('-' * 87)
                for i in res:
                    print(i.decode('utf-8').rstrip())
            else:
                print('-' * 87)
                print('Main routing table')
                print('-' * 87)
                print('N/A')

        except Exception as e:
            print(e)

    def show_cli_callback(self, key, param):
        # default 30 last commands history
        last = 30

        def is_valid_number(number):
            if isinstance(number, int) and (number <= 1 or number <= 5000):
                return True
            else:
                return False

        if not param:
            print('\nhistory    Show CLI history\n')
            return
        elif len(param) <= 4:
            if len(param) == 1 and re.match('^[?]$', param[0]):
                print('\nhistory    Show CLI history\n')
                return
            elif len(param) == 1 and not re.match('history', param[0]): 
                print('Invalid option: Available option is "history"')
                print('\nhistory    Show CLI history\n')
                return
            elif (len(param) == 1 and re.match('history[?]', param[0])) or \
                (len(param) == 2 and re.match('^[?]$', param[1])):
                print('\nlast <number>    Show CLI history for last N (1..5000)')
                print('Hit [Enter]\n')
                return
            elif len(param) == 2 and re.match('history', param[0]) and not re.match('last', param[1]):
                print('Invalid option: Available option is "last"')
                print('\nlast <number>    Show CLI history for last N (1..5000)\n')
                return
            elif (len(param) == 2 and re.match('history', param[0]) and re.match('last[?]', param[1])) or \
                (len(param) == 3 and re.match('history', param[0]) and re.match('^[?]$', param[2])):
                print('\nlast <number>    Show CLI history for last N (1..5000)\n')
                return
            elif len(param) == 3 and re.match('history', param[0]) and re.match('last', param[1]) and re.match('^\d+[?]$', param[2]):
                print('Hit [Enter]\n')
                return
            elif len(param) == 3 and re.match('history', param[0]) and re.match('last', param[1]):
                try:
                    if is_valid_number(int(param[2])):
                        last = param[2] 
                    else:
                        print("Invalid number: Enter a valid number from 1 to 5000\n")
                        return
                except ValueError:
                    print("Invalid number: Enter a valid number from 1 to 5000\n")
                    return
            elif len(param) == 4 and re.match('history', param[0]) and re.match('last', param[1]) and re.match('^[?]$', param[3]):
                print('Hit [Enter]\n')
                return

        try:
            cmd = "tail -n {} /var/log/aella/aella_cli.log | awk -F'|' '/Run command/{{print $1, $5}}' | \
                sed 's/,.*Run command:/ /' | sort -rn".format(last)

            p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            res = p.communicate()
            if res[0]:
                for i in res:
                    print(i.decode('utf-8').rstrip())

        except Exception as e:
            print(e)
        
    # Set command
    @log_cmd
    def do_set(self, line):
        """ Set command """
        return self._on_nested_command(line, self.set_command_help, self.set_command_callback)

    @staticmethod
    def set_password_callback(key, param):
        if len(param) > 0:
            print('\nset password <Enter>\t Press enter to input password and ctrl-D to abort\n')
            return
        subprocess.call("/usr/bin/passwd `awk -F: '{print $1}' /etc/passwd | grep -E '^(aella|stellar)$' | head -n 1`",
                        shell=True)

    def set_tz_callback(self, key, param):
        if len(param) == 0 or param[0] not in ALL_TIMEZONES:
            print("Unknow timezone. eg: 'America/Los_Angeles'")
            return
        else:
            cmd = "sudo timedatectl set-timezone '{}'".format(param[0])
            self.shell_cmd_exec(cmd)

    def set_time_callback(self, key, param):
        if not param or param[0].endswith('?') or len(param) < 2:
            print('\n<YYYY-MM-DD HH:MM:SS> \t Specify system date and time\n')
            return

        date = param[0]
        time = param[1]
        if len(date.split('-')) < 3:
            print('Wrong date format:', date)
            return
        if len(time.split(':')) < 3:
            print('Wrong time format:', time)
            return

        self.shell_cmd_exec('sudo date -s "' + date + " " + time + '"')

    def set_ntp_callback(self, key, param):
        if not param or param[0].endswith('?') or len(param) < 1:
            print('\n<NTP server> \t Specify NTP server name or IP address\n')
            return

        if not self.is_valid_hostname(param[0]):
            print('Invalid NTP hostname: Please enter the correct hostname')
            print('\n<NTP server> \t Specify NTP server name or IP address\n')
            return

        ntp_conf = "/etc/ntpsec/ntp.conf"
        if not os.path.exists(ntp_conf):
            ntp_conf = "/etc/ntp.conf"  # fallback

        p = re.escape(param[0])

        # remove existing same server lines (pool/server) (prefix match)
        cmd = ["grep", "-E", r"^(pool|server)\s+{0}(\S*)\s*$".format(p), ntp_conf]
        process = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.communicate()
        ret = process.wait()

        if ret == 0:
            cmd = ["sudo", "sed", "-E", "-i", r"/^(pool|server)\s+{0}(\S*)\s*$/d".format(p), ntp_conf]
            process = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            process.communicate()
            ret = process.wait()

        # prepend "pool <server>" to top of config
        cmd = "sudo sh -c \"printf '%s\\n' 'pool {0}' | cat - {1} > {1}.tmp && mv {1}.tmp {1}\"".format(param[0], ntp_conf)
        ret = subprocess.call(cmd, shell=True)

        if ret == 0:
            subprocess.call(["sudo", "systemctl", "restart", "ntpsec"])
            return "Succeed to set ntp {0}\n".format(param[0])
        else:
            print("Failed to set ntp {0}\n".format(param[0]))
            return "Failed to set ntp {0}\n".format(param[0])
    

    def unset_ntp_callback(self, key, param):
        if not param or param[0].endswith('?') or len(param) < 1:
            print('\n<NTP server> \t Specify NTP server name or IP address\n')
            return

        ntp_conf = "/etc/ntpsec/ntp.conf"
        if not os.path.exists(ntp_conf):
            ntp_conf = "/etc/ntp.conf"  # fallback

        p = re.escape(param[0])

        status = 0

        cmd = ["grep", "{0}".format(param[0]), ntp_conf]
        process = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.communicate()
        ret = process.wait()

        if ret == 0:
            cmd = ["sudo", "sed", "-E", "-i", r"/^(pool|server)\s+{0}(\S*)\s*$/d".format(p), ntp_conf]
            process = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            process.communicate()
            ret = process.wait()

        if ret == 0:
            subprocess.call(["sudo", "systemctl", "restart", "ntpsec"])
            return 0
        else:
            print("Failed to unset ntp {0}\n".format(param[0]))
            return 1
    

    def unset_interface_callback(self, key, param):
        if self.is_sensor_host_mode():
            self.unset_interface_sensor(param)
            return

        contents = list()

        if not param or param[0].endswith('?') or len(param) <= 3:
            if (len(param) == 0 or param[0] == '?'):
                print('\n<Interface Name>  Specify a supported interface (data1g or data10g)\n')
                return
            elif (len(param) == 1 and re.match('data1[0]?g[?]', param[0])) or \
                (len(param) == 1 and re.match('data1[0]?g', param[0])) or \
                (len(param) == 2 and re.match('data1[0]?g', param[0]) and param[1] == '?'):
                print('\nip         Unset the IP address on the interface {}'.format(param[0].rstrip('?')))
                print('gateway    Unset the default gateway on the interface {}'.format(param[0].rstrip('?')))
                print('restart    Restart network interface\n')
                return
            elif (len(param) == 1 and not re.match('data1[0]?g[?]', param[0])) or \
                (len(param) == 2 and not re.match('data1[0]?g', param[0]) and param[1] == '?') or \
                (len(param) == 2 and not re.match('data1[0]?g', param[0]) and re.match('ip|gateway|restart', param[1])):
                print('\n<Interface Name>  Specify a supported interface (data1g or data10g)\n')
                return
            elif len(param) == 2 and re.match('data1[0]?g', param[0]) and not re.match('ip|gateway|restart', param[1]):
                print('Invalid option: Available options are "ip", "gateway", and "restart"')
                print('\nip         Unset the IP address on the interface {}'.format(param[0]))
                print('gateway    Unset the default gateway on the interface {}'.format(param[0]))
                print('restart    Restart network interface\n')
                return
            elif (len(param) == 2 and re.match('data1[0]?g', param[0]) and re.match('ip[?]|gateway[?]|restart[?]', param[1])) or \
                (len(param) == 3 and re.match('data1[0]?g', param[0]) and re.match('ip|gateway|restart', param[1]) and param[2].endswith('?')):
                print("\nHit [Enter]\n")
                return
     
        interface = param[0]
        option = param[1]

        # safeguard to protect mgt interface configuration
        if not self.is_device_exist(interface):
           return
        if not re.match('data1[0]?g', interface):
            return
        if option == 'ip':
            contents.append('auto {}'.format(interface))
            contents.append('iface {} inet manual'.format(interface))
            if not self.update_interface_file(interface, contents):
                return
            print("Run 'unset interface {0} restart' command to apply the changes.\n".format(interface))

        elif option == 'gateway':
            try:
                # data1g or data10g use table 2
                cmd_show = 'ip route show table 2 | grep default'
                p = subprocess.Popen(cmd_show, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                res = p.communicate() 
                if not res[0]:
                    print('Cannot find the default gateway on the interface {}\n'.format(interface))
                    return 
                m = re.match('default\s+via\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+dev\s+(\w+)', res[0].decode('utf-8'))
                if not m.group(1) == interface:
                    print('Cannot delete the default gateway due to interface mismatch\n')
                    return
                cmd_del = 'ip route del {} table 2'.format(m.group(0).rstrip())
                p = subprocess.Popen(cmd_del, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                res = p.communicate()
                if res[1]:
                    print('Cannot delete the default gateway on the interface {} or the default gateway was deleted already\n'.format(interface))
                    print(res[1].decode('utf-8').rstrip())
                print('Successfully deleted the default gateway: {}\n'.format(m.group(0)))

            except Exception as e:
                print('Cannot delete the default gateway\n')

        elif option == 'restart':
             print('Restarting network interface. You need to use new IP address to reconnect...\n')
             self.restart_new_network_manager(interface)

    def complete_unset(self, text, line, begidx, endidx):
        if not text:
            completions = self.unset_command_help.keys()
        else:
            completions = [f for f in self.unset_command_help.keys() if f.startswith(text)]
        return completions

    # Unset command
    @log_cmd
    def do_unset(self, line):
        """ Unset command """
        return self._on_nested_command(line, self.unset_command_help, self.unset_command_callback)

    def show_version(self, key, param):
        print('')
        print('Appliance Version : 3.10.1-appliance')
        print('Hardware Revision : 1.5\n')
        self.shell_cmd_exec('cat /sys/class/dmi/id/product_name | awk \'{printf   "Product Name  : "$1}\'', crlf=False)
        self.shell_cmd_exec('sudo cat /sys/class/dmi/id/product_serial | awk \'{printf "Serial Number : "$1}\'', crlf=False)
        print('\nAppliance CPUs')
        print('------------------------------')
        self.shell_cmd_exec('lscpu | grep -E "^Thread|^Core|^Socket|^CPU\("', crlf=False)
        print('\nAppliance Memory')
        print('--------------------------------')
        self.shell_cmd_exec('cat /proc/meminfo  | egrep "Mem|Swap"', crlf=False)
        print('')

    def show_hostname(self, key, param):
        self.shell_cmd_exec('hostname')

    def is_valid_hostname(self, hostname):
        if hostname[-1] == ".":
            hostname = hostname[:-1]
        allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
        return all(allowed.match(x) for x in hostname.split("."))

    def set_hostname_callback(self, key, param):
        if not param or param[0].endswith('?') or len(param) < 1:
            print('\n<String> \t Specify hostname string\n')
            return
        hostname = param[0]
        if len(hostname) > 64:
            print('\nError: Hostname too long. Max length is 64.\n')
            return
        if not self.is_valid_hostname(hostname):
            print('\nError: Invalid hostname format.\n')
            return
        try:
            self.shell_cmd_exec('sudo sh -c \'sed -i "s/\<`hostname`\>/%s/g" /etc/hosts && hostname %s && echo %s > /etc/hostname\'' % (str(param[0]), str(param[0]), str(param[0])))
            print("Successfully set hostname")
        except:
            print("Failed to set hostname")

    @staticmethod
    def update_patch_history(patch_name, patch_history, log_file, success, msg):
        timestamp = str(datetime.datetime.now())
        state = "Fail"
        if success:
            state = "Success"
        patch_info = {"timestamp": timestamp,
                      "state": state}
        patch_history[patch_name] = patch_info
        try:
            with open(PATCH_HISTORY, 'w') as outfile:
                json.dump(patch_history, outfile, sort_keys=True, indent=4, ensure_ascii=False)
        except Exception as e:
            print(e)
        log_content = "Patch starts at {}\n".format(timestamp)
        log_content += "{}\nPatch result: {}".format(msg, state)
        try:
            wf = open(log_file, 'w')
            wf.write(str(log_content))
            wf.close()
        except Exception as e:
            print(e)

    def set_patches_callback(self, key, param):
        if not param or param[0].endswith('?') or len(param) < 1:
            print('\n<String> \t Specify patches string, use "set patch apply <patch_name>" to apply patch from StellarCyber\n')
            return
        patches = param[0]
        try:
            if patches == "apply":
                self.run_command_with_stderr("sudo mkdir -p {}".format(PATCH_LOG_DIR))
                if len(param) < 2 or param[1] == "?":
                    print('\n<String> \t Specify the Stellar patch name to apply\n')
                    return
                patch_name = param[1]
                log_file = "{}/{}.log".format(PATCH_LOG_DIR, patch_name)

                try:
                    with open(PATCH_HISTORY) as f:
                        patch_history = json.load(f)
                except Exception as e:
                    patch_history = {}

                url = "https://192.168.122.2:8443/hotfix/{}".format(patch_name)
                local_file = "{}/{}".format(PATCH_DIR, patch_name)
                cmd = ["wget", "--user={}".format(META_USER),
                       "--password={}".format(META_TOKEN), "-O",
                       local_file, "--no-check-certificate", url]
                res, msg = self.run_command_with_stderr(cmd)
                if not res:
                    error_msg = "Failed to download patch: {}".format(msg)
                    print(error_msg)
                    self.update_patch_history(patch_name, patch_history, log_file, False, error_msg)
                    return
                success, msg = self.run_command_with_stderr(["sudo", "dpkg", "-i", local_file])
                if success:
                    msg = "Success"
                self.update_patch_history(patch_name, patch_history, log_file, success, msg)
                print(msg)
            else:
                print("Applying updates...")
                cmd = "sudo apt -qq update && sudo apt -qqy install {0} && sudo apt clean".format(patches)
                self.shell_cmd_exec(cmd)
                print("Successfully apply updates")
        except Exception as e:
            print("Failed to apply updates {}".format(e))

    def set_autostart_callback(self, key, param):
        """Configure VM auto start"""
        if not param or len(param) < 1:
            print('\n<VM Name> [enable|disable]  Specify VM name and enable/disable auto start')
            print('                             If enable/disable is omitted, it will toggle the current state\n')
            return

        vm_name = param[0].rstrip('?')
        if param[0].endswith('?') or vm_name == '?':
            print('\n<VM Name> [enable|disable]  Specify VM name and enable/disable auto start')
            print('                             If enable/disable is omitted, it will toggle the current state\n')
            return

        # Check if VM exists
        vm_list = self.get_vm_list()
        if vm_name not in vm_list:
            print('VM "{}" not found. Available VMs: {}'.format(vm_name, ', '.join(vm_list) if vm_list else 'none'))
            return

        # Get enable/disable option
        enable = None
        if len(param) >= 2:
            option = param[1].lower().rstrip('?')
            if option == 'enable':
                enable = True
            elif option == 'disable':
                enable = False
            elif option == '?' or param[1].endswith('?'):
                print('\n<VM Name> [enable|disable]  Specify VM name and enable/disable auto start')
                print('                             If enable/disable is omitted, it will toggle the current state\n')
                return
            else:
                print('Invalid option: Available options are "enable" and "disable"')
                print('\n<VM Name> [enable|disable]  Specify VM name and enable/disable auto start\n')
                return

        # If enable/disable not specified, check current state and toggle
        if enable is None:
            try:
                cmd = "virsh dominfo {} | grep -i 'autostart'".format(vm_name)
                proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, err = proc.communicate()
                if out:
                    # Check if autostart is enabled
                    if 'enabled' in out.decode('utf-8', errors='ignore').lower():
                        enable = False  # Toggle to disable
                    else:
                        enable = True   # Toggle to enable
                else:
                    # If we can't determine, default to enable
                    enable = True
            except Exception:
                # If check fails, default to enable
                enable = True

        # Execute virsh autostart command
        try:
            if enable:
                cmd = "virsh autostart {}".format(vm_name)
                result = subprocess.call(cmd, shell=True)
                if result == 0:
                    print("VM '{}' auto start enabled successfully.\n".format(vm_name))
                else:
                    print("Failed to enable auto start for VM '{}'.\n".format(vm_name))
            else:
                cmd = "virsh autostart --disable {}".format(vm_name)
                result = subprocess.call(cmd, shell=True)
                if result == 0:
                    print("VM '{}' auto start disabled successfully.\n".format(vm_name))
                else:
                    print("Failed to disable auto start for VM '{}'.\n".format(vm_name))
        except Exception as e:
            print("Failed to configure auto start for VM '{}': {}\n".format(vm_name, e))

    # clear commands
    def clear_cli_callback(self, key, param):
        if len(param) <= 2:
            if not param or (len(param) == 1 and re.match('^[?]$',param[0])):  
                print('\nhistory    Clear CLI history\n')
                return
            elif (len(param) == 1 and not re.match('history', param[0])) or \
                (len(param) == 2 and not re.match('history', param[0])):
                print('Invalid option: Available option si "history"')
                print('\nhistory    Clear CLI history\n')
                return
            elif (len(param) == 1 and re.match('history[?]', param[0])) or \
                (len(param) == 2 and re.match('history', param[0]) and re.match('^[?]$', param[1])):
                print('\nHit [Enter]\n')
                return
        try:
            current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            cli_log_file  = '/var/log/aella/aella_cli.log'
            cli_log_backup = cli_log_file + '_' + current_time.replace(' ', '_').replace(':','')

            cmd = 'cp -a {0} {1}'.format(cli_log_file, cli_log_backup)
            p = subprocess.call(cmd, shell=True)
            if not p == 0:
                print('Failed copy: {}'.format(cmd))
            log_str = '{},000|INFO|0|log|Run command: ### clear cli history ###\n'.format(current_time)
            with open(cli_log_file, 'w') as f:
                f.write(log_str) 

            # Backup up to 5 cli history files
            cmd = 'ls -r /var/log/aella/aella_cli.log_*'
            p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            res = p.communicate()
            if res[0]:
                backup_files = res[0].decode('utf-8').split()
                old_backup_files = backup_files[5:]
                if old_backup_files:
                    for i in old_backup_files:
                        os.system('rm {}'.format(i))

        except Exception as e:
            print(e)

    def monitor_vm_callback(self, key, param):
        """Monitor VM resource usage or launch htop for a specific VM"""
        # Show help if explicitly requested
        if param and len(param) == 1 and (param[0] == '?' or param[0] == 'help'):
            print('\nhtop <VM Name>  Monitor specific VM with htop')
            print('                List all running VMs with resource usage\n')
            return
        
        # Handle 'monitor vm htop <vm_name>'
        if param and len(param) >= 1 and param[0] == 'htop':
            if len(param) < 2:
                print('\n<VM Name>  Specify VM name to monitor with htop\n')
                return
            vm_name = param[1].rstrip('?')
            if param[1].endswith('?') or vm_name == '?':
                print('\n<VM Name>  Specify VM name to monitor with htop\n')
                return
            
            # Find qemu PID for the VM
            pid_file = '/run/libvirt/qemu/{}.pid'.format(vm_name)
            if not os.path.exists(pid_file):
                print('VM "{}" not found or not running (PID file does not exist)\n'.format(vm_name))
                return
            
            try:
                with open(pid_file, 'r') as f:
                    pid = f.read().strip()
                # Execute htop in current TTY
                subprocess.call(['sudo', 'htop', '-p', pid])
            except Exception as e:
                print('Failed to launch htop for VM "{}": {}\n'.format(vm_name, e))
            return
        
        # Handle 'monitor vm' - list VMs with CPU/memory usage
        try:
            # Get running VMs
            cmd = "virsh list --name"
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = proc.communicate()
            if proc.returncode != 0:
                print('Failed to get VM list\n')
                return
            
            vm_list = [vm.strip() for vm in out.decode('utf-8', errors='ignore').split('\n') if vm.strip()]
            
            if not vm_list:
                print('No running VMs found\n')
                return
            
            # Print header
            print('\n{:<15} {:<8} {:<8} {:<10}'.format('VM', 'PID', 'CPU%', 'RSS(MB)'))
            print('-' * 45)
            
            # For each VM, get PID and resource usage
            for vm in vm_list:
                pid_file = '/run/libvirt/qemu/{}.pid'.format(vm)
                if not os.path.exists(pid_file):
                    continue  # Skip silently if PID file doesn't exist
                
                try:
                    with open(pid_file, 'r') as f:
                        pid = f.read().strip()
                    
                    # Get CPU and RSS using ps
                    cmd = "ps -p {} -o %cpu,rss --no-headers".format(pid)
                    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    out, err = proc.communicate()
                    
                    if proc.returncode == 0 and out:
                        parts = out.decode('utf-8', errors='ignore').strip().split()
                        if len(parts) >= 2:
                            cpu_percent = parts[0].strip()
                            rss_kb = int(parts[1].strip())
                            rss_mb = rss_kb / 1024.0
                            print('{:<15} {:<8} {:<8} {:<10.1f}'.format(vm, pid, cpu_percent, rss_mb))
                except Exception:
                    # Skip VM if we can't get its info
                    continue
            
            print('')
        except Exception as e:
            print('Failed to monitor VMs: {}\n'.format(e))

    def health_check_callback(self, key, param):
        """Check system health status"""
        try:
            # 1. CPU load
            try:
                with open('/proc/loadavg', 'r') as f:
                    loadavg = f.read().strip().split()
                    load_1min = float(loadavg[0])
                
                # Get CPU core count
                cmd = "nproc"
                proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, _ = proc.communicate()
                cpu_cores = int(out.decode('utf-8', errors='ignore').strip()) if out else 1
                
                if load_1min < cpu_cores:
                    print('[OK]   load: {:.1f} (cores={})'.format(load_1min, cpu_cores))
                else:
                    print('[WARN] load: {:.1f} (cores={})'.format(load_1min, cpu_cores))
            except Exception as e:
                print('[ERR]  load: failed to check ({})'.format(e))
            
            # 2. Memory availability
            try:
                with open('/proc/meminfo', 'r') as f:
                    meminfo = f.read()
                    mem_total = 0
                    mem_available = 0
                    for line in meminfo.split('\n'):
                        if line.startswith('MemTotal:'):
                            mem_total = int(line.split()[1])
                        elif line.startswith('MemAvailable:'):
                            mem_available = int(line.split()[1])
                
                if mem_total > 0:
                    mem_percent = (mem_available / mem_total) * 100
                    if mem_percent > 20:
                        print('[OK]   mem: {:.0f}% available'.format(mem_percent))
                    else:
                        print('[WARN] mem: {:.0f}% available'.format(mem_percent))
                else:
                    print('[ERR]  mem: failed to get memory info')
            except Exception as e:
                print('[ERR]  mem: failed to check ({})'.format(e))
            
            # 3. Swap usage
            try:
                with open('/proc/meminfo', 'r') as f:
                    meminfo = f.read()
                    swap_total = 0
                    swap_free = 0
                    for line in meminfo.split('\n'):
                        if line.startswith('SwapTotal:'):
                            swap_total = int(line.split()[1])
                        elif line.startswith('SwapFree:'):
                            swap_free = int(line.split()[1])
                
                if swap_total > 0:
                    swap_used_kb = swap_total - swap_free
                    swap_used_gb = swap_used_kb / (1024.0 * 1024.0)
                    if swap_used_kb > 0:
                        print('[WARN] swap: {:.1f}G used'.format(swap_used_gb))
                    else:
                        print('[OK]   swap: not in use')
                else:
                    print('[OK]   swap: not configured')
            except Exception as e:
                print('[ERR]  swap: failed to check ({})'.format(e))
            
            # 4. Root filesystem usage
            try:
                cmd = "df -h / | tail -1"
                proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, _ = proc.communicate()
                if out:
                    parts = out.decode('utf-8', errors='ignore').strip().split()
                    if len(parts) >= 5:
                        usage_str = parts[4].rstrip('%')
                        usage = int(usage_str)
                        if usage < 80:
                            print('[OK]   /: {}% used'.format(usage))
                        else:
                            print('[WARN] /: {}% used'.format(usage))
            except Exception as e:
                print('[ERR]  /: failed to check ({})'.format(e))
            
            # 5. /stellar filesystem usage (only if mount exists)
            try:
                if os.path.exists('/stellar'):
                    cmd = "df -h /stellar 2>/dev/null | tail -1"
                    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    out, _ = proc.communicate()
                    if out and out.strip():
                        parts = out.decode('utf-8', errors='ignore').strip().split()
                        if len(parts) >= 5:
                            usage_str = parts[4].rstrip('%')
                            usage = int(usage_str)
                            if usage < 80:
                                print('[OK]   /stellar: {}% used'.format(usage))
                            else:
                                print('[WARN] /stellar: {}% used'.format(usage))
            except Exception as e:
                pass  # Silently skip if /stellar doesn't exist or can't be checked
            
            # 6. libvirt service status
            try:
                # Try libvirtd first (older systems)
                cmd = "systemctl is-active libvirtd 2>/dev/null"
                proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, _ = proc.communicate()
                if proc.returncode == 0 and out:
                    status = out.decode('utf-8', errors='ignore').strip()
                    if status == 'active':
                        print('[OK]   libvirt: active')
                    else:
                        print('[WARN] libvirt: {}'.format(status))
                else:
                    # Try virtqemud (newer systems)
                    cmd = "systemctl is-active virtqemud 2>/dev/null"
                    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    out, _ = proc.communicate()
                    if proc.returncode == 0 and out:
                        status = out.decode('utf-8', errors='ignore').strip()
                        if status == 'active':
                            print('[OK]   libvirt: active')
                        else:
                            print('[WARN] libvirt: {}'.format(status))
                    else:
                        print('[WARN] libvirt: service not found')
            except Exception as e:
                print('[ERR]  libvirt: failed to check ({})'.format(e))
            
            print('')
        except Exception as e:
            print('Failed to check system health: {}\n'.format(e))

    @staticmethod
    def show_patch_history_callback(key, params):
        try:
            # If a patch is specified, display the detail log of the path
            patch = ""
            if params:
                patch = params[0]
            try:
                with open(PATCH_HISTORY) as f:
                    patch_history = json.load(f)
            except Exception as e:
                patch_history = {}
            if patch:
                if patch not in patch_history:
                    print("There is no history associated with specified patch")
                    return
                state = patch_history[patch].get("state", "Unknown")
                log_file = "{}/{}.log".format(PATCH_LOG_DIR,
                                              patch)
                if not os.path.isfile(log_file):
                    print("There is no history associated with specified patch")
                    return
                try:
                    rf = open(log_file, 'r')
                    patch_log = rf.read()
                    rf.close()
                except:
                    patch_log = ""
                output = "Patch state: {}".format(state)
                output += "\n=====================\n"
                output += patch_log
            # Only return summary
            else:
                res = []
                for patch_name in patch_history:
                    patch_info = patch_history.get(patch_name, {})
                    state = patch_info.get("state", "Unknown")
                    timestamp = patch_info.get("timestamp", "Unknown")
                    res.append("Patch name: {}".format(patch_name))
                    res.append("State:      {}".format(state))
                    res.append("Time:       {}".format(timestamp))
                    res.append("====================")
                if not res:
                    output = "No patch history"
                else:
                    output = "\n".join(res)
            print(output)
        except Exception as e:
            print("Failed to get patch history: {}".format(e))

    def update_interface_file(self, interface, contents):
        try:
            if interface == 'mgt':
                with open("/etc/network/interfaces", 'w') as f:
                    new_content = "\n".join(contents)
                    f.write(new_content)
            elif interface == 'data1g':
                with open("/etc/network/interfaces.d/01-data1g.cfg", 'w') as f:
                    new_content = "\n".join(contents)
                    f.write(new_content)
            elif interface == 'data10g':
                with open("/etc/network/interfaces.d/10-data10g.cfg", 'w') as f:
                    new_content = "\n".join(contents)
                    f.write(new_content)
            return True
        except Exception as e:
            print('Failed to update interface configuration')
            print(e)
            return False

    # Update gateway in the routing table 1 (mgt) or table 2 (data) by calling
    # /etc/network/if-up.d/dp_mgt_data script
    def update_dp_mgt_data(self, data_intf_gw, interface):
        try:
            with open('/etc/network/if-up.d/dp_mgt_data', 'rt') as f:
                content = f.read()
            new_content = re.sub(r'DATA_GATEWAY=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*', 'DATA_GATEWAY={0}'.format(data_intf_gw), content)
            with open('/etc/network/if-up.d/dp_mgt_data', 'wt') as f:
                f.write(new_content)
            return True
        except:
            print("Failed to update {0} interface gateway".format(interface))
            return False

    # Get the interface name out of a line from /etc/network/interfaces
    @staticmethod
    def get_interface_from_line(line):
        interface = ""
        tokens = re.match("\s*iface\s+(\S+)\s+inet\s+(\S+).*", line)
        if tokens:
            interface = tokens.group(1)
        else:
            auto_tokens = re.match("\s*auto\s+(\S+).*", line)
            if auto_tokens:
                interface = auto_tokens.group(1)
        return interface.strip()

    # Check interface existence
    @staticmethod
    def iface_exists(interface):
        try:
            cmd = "ifconfig {0} 2>/dev/null".format(interface)
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
            info = proc.communicate()[0].decode().rstrip()
            rc = proc.returncode
            if rc or info is None or info == "":
                return False
            return True
        except Exception:
            # print("interface {} not found".format(interface))
            return False

    # Convert cidr to netmask
    # It accepts 1.1.1.1/24 or 1.1.1.1/255.255.255.0
    @staticmethod
    def cidr_to_netmask(cidr):
        address, net_bits = cidr.split('/')
        if net_bits is None or net_bits == "":
            netmask = "255.255.255.255"
        else:
            if re.match("(\d+\.\d+\.\d+\.\d+)", net_bits):
                netmask = net_bits
            else:
                host_bits = 32 - int(net_bits)
                netmask = socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << host_bits)))
        if (not re.match("(\d+\.\d+\.\d+\.\d+)", netmask) or
                not re.match("(\d+\.\d+\.\d+\.\d+)", address)):
            address = ""
            netmask = ""
        return address, netmask

    def set_interface_callback2(self, param):
        status = 0
        output = None
        try:
            CLOUD_INIT_FILE = "/etc/network/interfaces.d/50-cloud-init.cfg"
            if os.path.isfile(CLOUD_INIT_FILE):
                # We add a newline before we copy over the
                # cloud init configure file. In previous version,
                # set interface cli will miss return/newline at the end of
                # /etc/network/interfaces file and old cli didn't take care
                # of cloud init file. Therefore if doing set interface
                # with new version of cli, which copies over the contents of
                # cloud init, the concatenation will have error due to the missing
                # newline.
                subprocess.call("sudo echo \"\" >> /etc/network/interfaces", shell=True)
                cmd = "sudo cat /etc/network/interfaces.d/50-cloud-init.cfg >> /etc/network/interfaces"
                proc = subprocess.Popen(cmd, shell=True)
                proc.wait()
                os.remove(CLOUD_INIT_FILE)
            interface = param[0]
            field = param[1]
            value = param[2]

            # Those fields are configurable.
            # Extract those fields from param
            # If a field is empty, it will not be configured
            network_mode = ""
            new_address = ""
            new_netmask = ""
            new_gateway = ""
            new_dns_server = ""
            if field.lower() == "ip":
                if value.lower() == "dhcp":
                    network_mode = "dhcp"
                else:
                    network_mode = "static"
                    new_address, new_netmask = self.cidr_to_netmask(value)
            if field.lower() == "gateway":
                new_gateway = value
            elif field.lower() == "dns":
                new_dns_server = ' '.join(param[2:])
            elif field.lower() == "restart":
                new_restart = value
            conf_f = open("/etc/network/interfaces", 'r')
            contents = []
            lines = conf_f.readlines()
            # A flag whether current line is in the block of
            # configuring the target interface
            is_iface_config_block = False

            # Whether the interface to configure is already in
            # /etc/network/interfaces, this flag is used
            # to determine at the end of parsing, if new interface
            # should be added to the interface file
            iface_exists = False

            # A flag indicating whether the target iface is actually
            # configured, this flag is used to make sure that
            # new configuration is always applied, no matter if an old
            # configuration already exists or not
            iface_configured = False

            netmask_configured = False

            # The flag of whether skipping non-existence iface
            skip_non_existing = False

            # Parse the file line by line, put/replace line and put
            # into new configuration
            for line in lines:
                line = line.rstrip()
                auto_pattern = "\s*auto {0}.*".format(interface)
                iface_pattern = "\s*iface {0}\s+.*".format(interface)
                auto_match = re.match(auto_pattern, line)
                iface_match = re.match(iface_pattern, line)
                current_iface = self.get_interface_from_line(line)

                # If this is a start of a configuration block
                # we check if that interface actually exists
                # If this iface does not exists, we need to skip following
                # lines until we met a valid interface
                if not current_iface == "":
                    if not self.iface_exists(current_iface):
                        print('{} - this line does not contain valid interface'.format(line))
                        skip_non_existing = True
                        continue
                    else:
                        skip_non_existing = False

                # If this line starts the configuration of the target interface
                if auto_match or iface_match:
                    is_iface_config_block = True
                    iface_exists = True
                if is_iface_config_block:
                    # If this is the line of iface .... inet ... static|dhcp
                    if iface_match:
                        # The original network mode
                        tokens = re.match("\s*iface\s+(\S+)\s+inet\s+(\S+).*", line)
                        raw_mode = tokens.group(2)
                        # Adjust the inet mode
                        if raw_mode == "static" and network_mode == "dhcp":
                            contents.append("iface {0} inet dhcp".format(interface))
                            iface_configured = True
                        elif raw_mode == "dhcp" and network_mode == "static":
                            contents.append("iface {0} inet static".format(interface))
                        else:
                            contents.append(line)
                            network_mode = raw_mode
                    elif auto_match:
                        contents.append(line)
                    # Matching the address line
                    elif re.match("\s*address\s+(.*)", line):
                        if network_mode == "dhcp":
                            print("DHCP does not need explicit address")
                        elif new_address:
                            contents.append("address {0}".format(new_address))
                            iface_configured = True
                        else:
                            contents.append(line)
                    # Matching the netmask line
                    elif re.match("\s*netmask\s+(.*)", line):
                        if network_mode == "dhcp":
                            print("DHCP does not need explicit address")
                        elif new_netmask:
                            contents.append("netmask {0}".format(new_netmask))
                            netmask_configured = True
                            iface_configured = True
                        else:
                            contents.append(line)
                    # Matching the gateway line
                    elif re.match("\s*gateway\s+.*", line):
                        if network_mode == "dhcp":
                            print("DHCP does not need explicit address")
                        elif new_gateway:
                            contents.append("gateway {0}".format(new_gateway))
                            iface_configured = True
                        else:
                            contents.append(line)
                    # Matching the dns line, for dns, we do append instead of overwrite
                    elif re.match("\s*dns-nameservers\s+(.*)", line):
                        if new_dns_server:
                            contents.append("dns-nameservers {0}".format(new_dns_server))
                            iface_configured = True
                        else:
                            contents.append(line)
                    # The end of the configuration block of the target interface,
                    # if no configure is applied yet, apply the new configuration.
                    # The creteria is that this line is started with "auto" or "iface"
                    # but the interface name is not the configuration target interface.
                    # If the iface_configured is not set, apply the configuration
                    # at this point
                    elif (not auto_match and not iface_match and
                          (re.match("\s*auto .*", line) or re.match("\s*iface .*", line))):
                        if not iface_configured:
                            if not new_address == "":
                                contents.append("address {0}".format(new_address))
                            if not new_netmask == "":
                                contents.append("netmask {0}".format(new_netmask))
                            if not new_gateway == "":
                                contents.append("gateway {0}".format(new_gateway))
                            if not new_dns_server == "":
                                contents.append("dns-nameservers {0}".format(new_dns_server))
                            iface_configured = True
                        elif not new_netmask == "" and not netmask_configured and not network_mode == "dhcp":
                            contents.append("netmask {0}".format(new_netmask))
                            netmask_configured = True
                        # Exiting the target configuration block
                        contents.append(line)
                        is_iface_config_block = False
                    else:
                        # Irrelevant lines
                        contents.append(line)
                else:
                    # Lines that are irrelevant to current configurations,
                    # keep them untouched in new configuration
                    if not skip_non_existing:
                        # If this line belongs to an existing interface
                        # will new configuration include it
                        contents.append(line)
            if iface_exists is False:
                # Add a new entry
                if field == "ip":
                    contents.append("auto {0}".format(interface))
                    if network_mode == "dhcp":
                        contents.append("iface {0} inet dhcp".format(interface))
                    else:
                        contents.append("iface {0} inet static".format(interface))
                        contents.append("address {0}".format(new_address))
                        contents.append("netmask {0}".format(new_netmask))
            # Interface exists but not configured yet
            # This is for corner case where the target interface is the last
            # interface in configuration file
            # e.g. the last line is
            # iface target inet dhcp
            # and the new set is static with ip
            elif iface_configured is False:
                if not new_address == "":
                    contents.append("address {0}".format(new_address))
                if not new_netmask == "":
                    contents.append("netmask {0}".format(new_netmask))
                if not new_gateway == "":
                    contents.append("gateway {0}".format(new_gateway))
                if not new_dns_server == "":
                    contents.append("dns-nameservers {0}".format(new_dns_server))
            elif not new_netmask == "" and not netmask_configured and not network_mode == "dhcp":
                contents.append("netmask {0}".format(new_netmask))
                netmask_configured = True
            #contents.append("\n") . If this line exists, extra empty line will be added whenever you execute "set interface" command
            conf_f.close()
            # Now the parsing is finished, update interface file
            # DEBUG: print("{0}".format(contents))
            if not self.update_interface_file(interface, contents):
                status = 1
                return
            self.update_resolve_conf(new_dns_server)
            if field.lower() == "restart":
                print('Restarting network interface. You need to use new IP address to reconnect...\n')
                #self.restart_network_manager(interface, new_address, new_netmask, new_gateway)
                self.restart_new_network_manager(interface)
            if not (field.lower() == "restart"): 
                print("Run 'set interface {0} restart' command to apply the changes.\n".format(interface))

        except Exception as e:
            status = 1
            print("Failed to set interface: {} ".format(e))
        return status, output

    # Handle to configure data interfaces
    def set_interface_callback3(self, param):
        interface = param[0]
        field = param[1]
        value = param[2]
        current_address = ''
        current_netmask = ''
        current_gateway = ''
        new_address = ''
        new_netmask = ''
        new_gateway = ''
        current_contents = list()
        contents = list()
        is_ip_change = False
        is_gateway_change = False
        require_interface_restart = False

        if not self.is_device_exist(interface):
            return
        if field.lower() == 'ip':
            new_address, new_netmask = self.cidr_to_netmask(value)
            is_ip_change = True
        if field.lower() == 'gateway':
            new_gateway = value
            is_gateway_change = True
        elif field.lower() == "restart":
            new_restart = value
            require_interface_restart = True

        if interface == 'data1g':
            try:
                with open("/etc/network/interfaces.d/01-data1g.cfg", 'r') as f:
                    current_contents = f.readlines()
            except Exception as e: 
                print(e)
                return
        if interface == 'data10g':
            try:
                with open("/etc/network/interfaces.d/10-data10g.cfg", 'r') as f:
                    current_contents = f.readlines()
            except Exception as e:
                print(e)
                return

        for line in current_contents:
            if re.match('\s*address\s+.*', line):
                current_address = re.match('\s*address\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line).group(1)
            if re.match('\s*netmask\s+.*', line):
                current_mask = re.match('\s*netmask\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line).group(1)

        if is_ip_change:
            contents.append('auto {}'.format(interface))
            contents.append('iface {} inet static'.format(interface)) 
            contents.append('address {}'.format(new_address))
            contents.append('netmask {}'.format(new_netmask))
            if not self.update_interface_file(interface, contents):
                return

        elif is_gateway_change:
            if not current_address or not current_mask: 
                print('Please configure IP address and netmask prior to configuring "{}" interface gateway'.format(interface))
                print('set interface {} ip <IP Address/Netmask>\n'.format(interface))
                return
            self.update_dp_mgt_data(new_gateway, interface) 

        elif require_interface_restart:
             print("Restarting network interface. You need to use new IP address to reconnect...\n")
             self.restart_new_network_manager(interface)

        if not (field.lower() == "restart"):
             print("Run 'set interface {0} restart' command to apply the changes.\n".format(interface))

        return None

    # Update resolve.conf
    def update_resolve_conf(self, dns_server):
        if dns_server == "":
            return True
        try:
            write_f = open("/etc/resolv.conf", 'w')
            write_f.write("nameserver {0}\n".format(dns_server))
            write_f.close()
            return True
        except Exception:
            print("Failed to write to resolv.conf")
            return False

    @staticmethod
    def restart_new_network_manager(interface, gw=True):
        try:
            cmd = "( rm -f /run/resolvconf/interface/{0}.dhclient && ip address flush dev {0} && ifdown {0} 2> /dev/null && ifup {0} 2>/dev/null )&".format(interface)
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            proc.communicate()
        except Exception as e:
            print("Failed to restart networking! {}".format(e))
            return False
        return True

    # Restart network manager to make configuration active
    @staticmethod
    def restart_network_manager(interface, address, netmask, new_gateway):
        try:
            if not address == "":
                cmd = "ifconfig {0} 0.0.0.0; ifconfig {1} {2} netmask {3}".format(interface, interface, address, netmask)
                proc = subprocess.Popen(cmd, shell=True)
                proc.wait()
            elif not new_gateway == "":
                cmd = "ip route del default"
                proc = subprocess.Popen(cmd, shell=True)
                proc.wait()
                cmd = "ip route add default via {0}".format(new_gateway)
                proc = subprocess.Popen(cmd, shell=True)
                proc.wait()
            cmd = "/etc/init.d/networking restart"
            proc = subprocess.Popen(cmd, shell=True)
            proc.wait()
        except Exception:
            print("Failed to restart networking!")
            return False
        return True

    def is_device_exist(self, interface):
        cmd = 'ip link show {}'.format(interface)
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output, err = p.communicate()

        if re.match('Device "{}" does not exist'.format(interface), err.decode('utf-8')):
            print('Device "{}" does not exist. Is it used by other virtual machine?'.format(interface))
            return False
        return True


    def set_interface_callback(self, key, param):
        if self.is_sensor_host_mode():
            self.set_interface_sensor(param)
            return

        if not param or param[0].endswith('?') or len(param) <= 4:
            if (len(param) < 1 or (len(param) == 1 and param[0] == '?')) or \
                (len(param) == 1 and not re.match('mgt|data1[0]?g', param[0])) or \
                (len(param) == 2 and not re.match('mgt|data1[0]?g', param[0]) and param[1] == '?'):
                print('\n<Interface Name>  Specify a supported interface name (mgt, data1g, data10g)\n')
                return
            elif (len(param) == 1 and re.match('mgt', param[0])) or \
                (len(param) == 1 and re.match('mgt[?]', param[0])) or \
                (len(param) == 2 and re.match('mgt', param[0]) and param[1] == '?'):
                print('\nip <IP Address/Netmask>   Specify interface IP address and netmask')
                print('gateway <IP Address>      Specify default gateway IP address')
                print('dns <IP Address> [...]    Specify single DNS server IP address or multiple DNS separated by space')
                print('restart                   Restart network interface\n')
                return
            elif (len(param) == 1 and re.match('data1[0]?g', param[0])) or \
                (len(param) == 1 and re.match('data1[0]?g[?]', param[0])) or \
                (len(param) == 2 and re.match('data1[0]?g', param[0]) and param[1] == '?'):
                print('\nip <IP Address/Netmask>   Specify interface IP address and netmask')
                print('gateway <IP Address>      Specify default gateway IP address')
                print('restart                   Restart network interface\n')
                return
            elif len(param) == 2 and not re.match('ip|gateway|dns|restart', param[1]):
                print('Invalid option: Available options are "ip", "gateway", "dns" and "restart"')
                print('\nip <IP Address/Netmask>   Specify interface IP address and netmask')
                print('dns <IP Address> [...]    Specify DNS server IP address or addrsses separated by space')
                print('gateway <IP Address>      Specify default gateway IP address')
                print('restart                   Restart network interface\n')
                return
            elif (len(param) == 2 and param[1].endswith('ip?')) or \
                (len(param) == 3 and param[1] == 'ip' and not self.valid_ipv4_address(param[2].rstrip('?'))):
                print('\n<IP Address/Netmask>   Specify interface IP address and netmask\n')
                return
            elif (len(param) == 2 and param[1].endswith('gateway?')) or \
                (len(param) == 3 and param[1] == 'gateway' and not self.valid_ipv4_address(param[2].rstrip('?'))):
                print('\n<IP Address>      Specify default gateway IP address\n')
                return
            elif (len(param) == 2 and param[1].endswith('dns?')) or \
                (len(param) == 3 and param[1] == 'dns' and param[2].endswith('?')):
                print('\n<IP Address> [...]    Specify DNS server IP address or addrsses separated by space\n')
                return
            elif (len(param) == 2 and param[1].endswith('restart?')) or \
                (len(param) == 3 and param[1] == 'restart' and param[2].endswith('?')):
                print('\nHit [Enter]\n')
                return
            elif (len(param) == 3 and param[1] == 'ip' and self.valid_ipv4_address(param[2].rstrip('?')) and param[2].endswith('?')) or \
                (len(param) == 4 and param[1] == 'ip' and self.valid_ipv4_address(param[2]) and param[3] == '?'):
                print('\nHit [Enter]\n')
                return
            elif (len(param) == 3 and param[1] == 'gateway' and self.valid_ipv4_address(param[2].rstrip('?')) and param[2].endswith('?')) or \
                (len(param) == 4 and param[1] == 'gateway' and self.valid_ipv4_address(param[2]) and param[3] == '?'):
                if not (re.match('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', param[2]) or \
                    re.match('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', param[2].rstrip('?'))):
                    print('Invalid gateway IP address format:')
                    print('\n<IP Address>      Specify default gateway IP address\n')
                    return
                print('\nHit [Enter]\n') 
                return

        interface = param[0]
        option = param[1]
        try:
            ip_address = param[2]
        except Exception:
            ip_address = ''
            param.append('')

        supported_interfaces = ['mgt', 'data1g', 'data10g']
        if interface not in supported_interfaces:
            print('Invalid interface name: Specify a supported interface name (mgt, data1g, data10g)')
            return
        # DP Appliance does NOT support dhcp on any interfaces
        #if option == 'dns' and (interface == 'data0'):
        #    print('Invalid option: only "mgt" interface support dns option')
        #    return

        if not self.is_device_exist(interface):
           return

        if option != 'ip' and option != 'gateway' and option != 'dns' and option != 'restart':
            print('Invalid option: {0}'.format(option))
            return
        if option == 'ip':
            #if ip_address != 'dhcp' and len(ip_address.split('.')) < 4:
            if ip_address != 'dhcp' and not self.valid_ipv4_address(ip_address):
                print('Invalid IP address format: {0}'.format(ip_address))
                return
            if ip_address != 'dhcp' and ip_address.find('/') < 0:
                print('Please specify network mask: {0}'.format(ip_address))
                return
            if ip_address == 'dhcp':
                print("Invalid ip option: DHCP client is not supported")
                return
        if option == 'gateway':
            gw_address = param[2]
            if not self.valid_ipv4_address(gw_address) or not re.match('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', gw_address):
                print('Invalid gateway IP address format: {0}'.format(gw_address))
                print('\n<IP Address>      Specify default gateway IP address\n')
                return
        if option == 'dns':
            dns_address = param[2:]
            exist_valid_dns_ip = 0
            if interface == 'data1g' or interface == 'data10g':
                print('Invalid option: Only "mgt" interface support dns option')
                return
            for i in range(0,len(dns_address)):
                if self.valid_ipv4_address(dns_address[i]):
                    exist_valid_dns_ip = 1
                elif dns_address[i] == '?' and exist_valid_dns_ip == 1:
                    print('\nHit [Enter]\n')
                    return
                elif not self.valid_ipv4_address(dns_address[i]):
                    print('Invalid DNS server IP address format: {0}'.format(dns_address[i]))
                    return

        if not interface == 'mgt':
            self.set_interface_callback3(param)
            return
        self.set_interface_callback2(param)

    def valid_ipv4_address(self, address):
        if '/' in address:
            a = address.split('/')
            if len(a[0].split('.')) < 4 or len(a[0].split('.')) > 4: 
                return
            m1 = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", a[0])
            if len(a[0].split('.')) == 4 and '.' in a[1]:
                if len(a[1].split('.')) < 4 or len(a[1].split('.')) > 4:
                    return
                elif len(a[1].split('.')) == 4 and a[1].endswith('?'):
                    m2 = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", a[1].strip('?'))
                    return bool(m1) and all(map(lambda n: 0 <= int(n) <= 255, m1.groups())) and \
                        bool(m2) and all(map(lambda n: 0 <= int(n) <= 255, m2.groups()))
                elif len(a[1].split('.')) == 4:
                    m2 = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", a[1])
                    return bool(m1) and all(map(lambda n: 0 <= int(n) <= 255, m1.groups())) and \
                        bool(m2) and all(map(lambda n: 0 <= int(n) <= 255, m2.groups()))

            if len(a[0].split('.')) == 4 and len(a[1]) == 2:
                m3 = re.match(r"^(\d{1,2})$", a[1])
                return bool(m1) and all(map(lambda n: 0 <= int(n) <= 255, m1.groups())) and \
                    bool(m3) and all(map(lambda n: 0 <= int(n) <= 32, m3.groups()))
            if len(a[0].split('.')) == 4 and len(a[1]) == 3 and a[1].endswith('?'):
                m3 = re.match(r"^(\d{1,2})$", a[1].strip('?'))
                return bool(m1) and all(map(lambda n: 0 <= int(n) <= 255, m1.groups())) and \
                    bool(m3) and all(map(lambda n: 0 <= int(n) <= 32, m3.groups()))
        else:
            if len(address.split('.')) < 4 or len(address.split('.')) > 4:
                return
            elif len(address.split('.')) == 4:
                m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", address)
                return bool(m) and all(map(lambda n: 0 <= int(n) <= 255, m.groups()))
         
    def complete_set_interface(self, text, line, begidx, endidx):
        options = ['ip', 'gateway', 'dns']
        if line.find('en') >= 0 or line.find('eth') >= 0 or \
           line.find('br0-aio') >= 0 or line.find('mgt') >= 0 or line.find('xmgt') >= 0 or line.find('data') >= 0:
            completion_set = options
        else:
            interfaces = os.listdir('/sys/class/net/')
            interfaces.remove('virbr0')
            interfaces.remove('virbr0-nic')
            completion_set = interfaces

        if not text:
            completions = completion_set
        else:
            completions = [f for f in completion_set if f.startswith(text)]
        return completions

    def complete_set(self, text, line, begidx, endidx):
        if not text and not line.startswith('set'):
            completions = self.set_command_help.keys()
        elif line.startswith('set interface'):
            return self.complete_set_interface(text, line, begidx, endidx)
        else:
            completions = [f for f in self.set_command_help.keys() if f.startswith(text)]
        return completions

    def complete_monitor(self, text, line, begidx, endidx):
        """Tab completion for monitor command"""
        if not text:
            completions = self.monitor_command_help.keys()
        elif line.startswith('monitor vm'):
            # Handle 'monitor vm htop <vm>'
            parts = line.split()
            if len(parts) == 3 and parts[2] == 'htop':
                # Complete VM names for htop
                vm_list = self.get_vm_list()
                if not text:
                    return vm_list
                return [vm for vm in vm_list if vm.startswith(text)]
            elif len(parts) == 2:
                # Complete subcommands after 'monitor vm'
                if not text:
                    return ['htop']
                return ['htop'] if 'htop'.startswith(text) else []
            else:
                completions = [f for f in self.monitor_command_help.keys() if f.startswith(text)]
        else:
            completions = [f for f in self.monitor_command_help.keys() if f.startswith(text)]
        return completions

    def complete_health(self, text, line, begidx, endidx):
        """Tab completion for health command"""
        if not text:
            completions = self.health_command_help.keys()
        else:
            completions = [f for f in self.health_command_help.keys() if f.startswith(text)]
        return completions

    # Check to see whether service port opened or not
    def service_is_running(self, service_port):
        cmd = ('netstat -lnt | grep ":%d " | wc -l' % service_port)
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        running = int(proc.stdout.read())
        return running

    def run_command_with_stderr(self, cmd):
        try:
            if type(cmd) is list:
                is_shell = False
            else:
                is_shell = True
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, shell=is_shell)
            result = proc.communicate()
            data = result[0]
            error = result[1]
            if proc.returncode != 0:
                return False, error
            return True, data
        except Exception as e:
            return False, str(e)

    # Execute shell command
    def shell_cmd_exec(self, line, crlf=True):
        proc = subprocess.Popen(line, shell=True, stdout=subprocess.PIPE)
        out, _ = proc.communicate()
        if out:
            output = out.strip().decode("utf-8")
            if crlf:
                print('\n{}\n'.format(output))
            else:
                print('{}'.format(output))
        return proc.returncode == 0

    def system_is_container(self):
        cmd = 'grep "docker\|kubepods" /proc/1/cgroup > /dev/null 2>&1'
        status = subprocess.call(cmd, shell=True)
        if status == 0:
            return True
        return False

    # Disk encrypt command
    @log_cmd
    def do_disk_encrypt(self, line):
        """ Disk encrypt command """
        return self._on_nested_command(line, self.disk_encrypt_command_help, self.disk_encrypt_command_callback)

    @staticmethod
    def _print_caution_banner(text='caution!', font='starwars'):
        termcolor.cprint(pyfiglet.figlet_format(text, font=font), 'red', attrs=['bold'])

    def _print_data_loss_warning(self, message="\nWARNING: This will cause data loss."):
        self._print_caution_banner()
        print(message)

    def _create_disk_encrypt_callback(self, callback):
        @functools.wraps(callback)
        def wrapper(*args, **kwargs):
            self.deu.with_lock(callback, *args, **kwargs)
        return wrapper

    def _on_disk_encrypt_enable_callback(self, key, param):
        if len(param) >= 1:
            return

        source_device = "/dev/vg_dl/lv_dl"
        proc = subprocess.Popen("sudo test -L {}".format(source_device), shell=True)
        proc.communicate()
        if proc.returncode != 0:
            self.deu.print_log('Failed to find device {}'.format(source_device), level=logging.ERROR)
            return

        self._print_data_loss_warning(
            "\nWARNING: This will cause data loss. When you enable disk encryption, "
            "we reformat the file system and all data is lost. If you want to keep existing data, "
            "please make a backup and restore when encryption finishes. And this only ensures that the related data "
            "locating in the appliance is encrypted at rest. The encryption of backups outside the appliance "
            "depends on the configuration of external storage itself.")
        if not self.deu.double_confirm():
            return

        if not self.deu.ensure_mod_dm_crypt():
            return

        stopped_vm_names = set()
        for vm in self.deu.get_vm_names():
            if not self.deu.shutdown_vm(vm):
                for stopped_vm in stopped_vm_names:
                    self.deu.start_vm(stopped_vm)
                return

        # open encrypted disk
        # use same name. because we don't change vm disk setting
        target_name = "encrypted-vg_dl-lv_dl"

        # remove opened disk first
        original_device = '/dev/mapper/{}'.format(target_name)
        proc = subprocess.Popen("sudo test -L {}".format(original_device), shell=True)
        proc.communicate()
        if proc.returncode == 0:
            self.deu.print_log(
                "\nWARNING: Found that device {} is still in use and "
                "re-enable will cause data loss.".format(source_device))
            if not self.deu.double_confirm():
                return
            if not self.deu.close_encrypted_disk(target_name):
                return

        delay = 3
        print("\nWARNING: This will cause data loss and reboot appliance in {} minutes. "
              "During the bootstrap of appliance, you can enter passphrase to open encrypted disk "
              "if you have console access. Otherwise, the DL VM will not start. "
              "You need manually start DL VM using appliance CLI:\n"
              "1. run `disk_encrypt open` to open encrypt disk\n"
              "2. run `start dl-master` to start DL VM\n"
              "3. run `show service` to check the status of VM\n".format(delay))
        if not self.deu.double_confirm():
            return

        passwd = self.deu.generate_passphrase()
        print("Here is your passphrase for disk encryption. You will not be able to view this passphrase again, "
              "so be sure to record it securely.\n{}\n".format(passwd))
        if not self.deu.setup_disk_encryption(source_device, passwd):
            return

        # avoid notification for all users
        self.deu.disable_systemd_services()

        if not self.deu.open_encrypted_disk(source_device, target_name):
            return
        if not self.deu.format_disk(target_name):
            return

        if not self.deu.enable_encrypted_symlink(target_name):
            return
        if not self.deu.update_crypttab(source_device, target_name):
            return
        if not self.deu.update_header_backups(source_device, self.deu.get_digest(passwd)):
            return

        self.deu.print_log('The disk encryption of {} is enabled.'.format(source_device))

        proc = subprocess.Popen("sudo shutdown -r +{}".format(delay), stderr=subprocess.PIPE, shell=True)
        _, err = proc.communicate()
        if proc.returncode != 0:
            self.deu.print_log('Failed to schedule the reboot of appliance', level=logging.ERROR)
            return

        message = 'Shutdown scheduled after {} minutes.'.format(delay)
        if err:
            parts = err.decode("utf-8").split(",")
            if len(parts) >= 1:
                message = parts[0]
        self.deu.print_log(message)

    def _on_disk_encrypt_disable_callback(self, key, param):
        target_name, source_device = self.deu.read_crypttab()
        if not target_name:
            self.deu.print_log('The disk encryption is not enabled.')
            return

        self._print_data_loss_warning(
            "\nWARNING: This will cause data loss. When you disable disk encryption, "
            "we reformat the file system and all data is lost. If you want to keep existing data, "
            "please make a backup and restore when encryption is disabled.")
        if not self.deu.double_confirm():
            return False

        if not self.deu.validate_disk_encryption(source_device):
            return

        stopped_vm_names = set()
        for vm in self.deu.get_vm_names():
            if not self.deu.shutdown_vm(vm):
                for stopped_vm in stopped_vm_names:
                    self.deu.start_vm(stopped_vm)
                return

        # avoid notification for all users
        self.deu.disable_systemd_services()

        # try closing disk anyway
        self.deu.close_encrypted_disk(target_name, print_error=False)

        # destroy header
        proc = subprocess.Popen("sudo cryptsetup erase {}".format(source_device),
                                stderr=subprocess.PIPE, shell=True)
        _, err = proc.communicate()
        if proc.returncode != 0:
            self.deu.print_log("Failed to erase header: {}".format(err.decode("utf-8")), level=logging.ERROR)
            return

        new_target_name = "vg_dl-lv_dl"
        if not self.deu.disable_encrypted_symlink(new_target_name):
            return
        # remove cryptsetup
        if not self.deu.remove_crypttab(source_device, target_name):
            return
        # format plain disk
        if not self.deu.format_disk(new_target_name):
            return

        for stopped_vm in self.deu.get_vm_names(running=False):
            self.deu.start_vm(stopped_vm)

        self.deu.print_log('The disk encrypt of {} is disabled.'.format(source_device))

    def _on_disk_encrypt_open_callback(self, key, param):
        if len(param) >= 1:
            return

        target_name, source_device = self.deu.read_crypttab()
        if not target_name:
            self.deu.print_log('The disk encryption is not enabled.')
            return

        running_vm_names = self.deu.get_vm_names()
        if running_vm_names:
            self.deu.print_log(
                'Found running vm {} and please shut them down first.'.format(','.join(running_vm_names)))
            return

        if not self.deu.open_encrypted_disk(source_device, target_name):
            return

        target_name = "encrypted-vg_dl-lv_dl"
        if not self.deu.enable_encrypted_symlink(target_name):
            return
        self.deu.print_log('The encrypted disk {} is open.'.format(source_device))

    def _on_disk_encrypt_close_callback(self, key, param):
        if len(param) >= 1:
            return

        target_name, source_device = self.deu.read_crypttab()
        if not target_name:
            self.deu.print_log('The disk encryption is not enabled.')
            return

        running_vm_names = self.deu.get_vm_names()
        if running_vm_names:
            self.deu.print_log(
                'Found running vm {} and please shut them down first.'.format(','.join(running_vm_names)))
            return

        if not self.deu.close_encrypted_disk(target_name):
            return
        self.deu.print_log('The encrypted disk {} is closed.'.format(source_device))

    def _on_disk_encrypt_add_key_callback(self, key, param):
        if len(param) >= 1:
            return

        target_name, source_device = self.deu.read_crypttab()
        if not target_name:
            self.deu.print_log('The disk encryption is not enabled.')
            return

        if self.deu.get_available_key_slots(source_device) <= 0:
            self.deu.print_log("Failed to add key: no available key slots.")
            return

        passwd = self.deu.generate_passphrase()
        print("Here is the recommended new passphrase. You will not be able to view this passphrase again, "
              "so be sure to record it securely.\n{}\n".format(passwd))
        proc = subprocess.Popen("sudo cryptsetup luksAddKey {}".format(source_device),
                                stderr=subprocess.PIPE, shell=True)
        _, err = proc.communicate()
        if proc.returncode != 0:
            self.deu.print_log("Failed to add key: {}".format(err.decode("utf-8")), level=logging.ERROR)
            return

        self.deu.update_header_backups(source_device, self.deu.get_digest(passwd))
        self.deu.print_log('The new passphrase is added.')

    def _on_disk_encrypt_remove_key_callback(self, key, param):
        if len(param) >= 1:
            return

        target_name, source_device = self.deu.read_crypttab()
        if not target_name:
            self.deu.print_log('The disk encryption is not enabled.')
            return

        if self.deu.is_last_key(source_device):
            self.deu.print_log("Failed to remove key: can't remove last passphrase.")
            return

        self._print_caution_banner()
        proc = subprocess.Popen("sudo cryptsetup luksRemoveKey {}".format(source_device),
                                stderr=subprocess.PIPE, shell=True)
        _, err = proc.communicate()
        if proc.returncode != 0:
            self.deu.print_log("Failed to remove key: {}".format(err.decode("utf-8")), level=logging.ERROR)
            return

        self.deu.update_header_backups(source_device, 'remove')
        self.deu.print_log('The passphrase is removed.')

    def _on_disk_encrypt_change_key_callback(self, key, param):
        if len(param) >= 1:
            return

        target_name, source_device = self.deu.read_crypttab()
        if not target_name:
            self.deu.print_log('The disk encryption is not enabled.')
            return

        passwd = self.deu.generate_passphrase()
        print("Here is the recommended new passphrase. You will not be able to view this passphrase again, "
              "so be sure to record it securely.\n{}\n".format(passwd))
        proc = subprocess.Popen("sudo cryptsetup luksAddKey {}".format(source_device),
                                stderr=subprocess.PIPE, shell=True)
        _, err = proc.communicate()
        if proc.returncode != 0:
            self.deu.print_log('Failed to create new passphrase: {}'.format(err.decode("utf-8")), level=logging.ERROR)
            return

        proc = subprocess.Popen("sudo cryptsetup luksRemoveKey {}".format(source_device),
                                stderr=subprocess.PIPE, shell=True)
        _, err = proc.communicate()
        if proc.returncode != 0:
            self.deu.print_log('Failed to remove old passphrase: {}'.format(err.decode("utf-8")), level=logging.ERROR)
            return

        self.deu.update_header_backups(source_device, self.deu.get_digest(passwd))
        self.deu.print_log('The passphrase is changed.')

    def _on_disk_encrypt_backup_header_callback(self, key, param):
        if len(param) != 1:
            print('Please specify /path/to/backup/file.')
            return
        if param[0].endswith("?"):
            print('\n<Backup File>         Specify the absolute path of backup file\n')
            return
        backup_file = param[0]

        target_name, source_device = self.deu.read_crypttab()
        if not target_name:
            self.deu.print_log('The disk encryption is not enabled.')
            return

        self._print_caution_banner()
        print("\nWARNING: This backup file and a passphrase valid at the time of backup allows decryption of the {} "
              "data area, even if the passphrase was later changed or removed from the device. Also note that "
              "with header backup you lose the ability to securely wipe the device by just overwriting the "
              "header.".format(source_device))
        if not self.deu.double_confirm():
            return

        if not self.deu.create_header_backup(source_device, backup_file):
            return
        self.deu.print_log('The header of {} is copied to {}.'.format(source_device, backup_file))

    def _on_disk_encrypt_restore_header_callback(self, key, param):
        if len(param) != 1:
            print('Please specify /path/to/backup/file.')
            return
        if param[0].endswith("?"):
            print('\n<Backup File>         Specify the absolute path of backup file\n')
            return

        backup_file = param[0]
        proc = subprocess.Popen("sudo test {}".format(backup_file), shell=True)
        proc.communicate()
        if proc.returncode != 0:
            self.deu.print_log("Backup file {} doesn't exist.".format(backup_file))
            return

        target_name, source_device = self.deu.read_crypttab()
        if not target_name:
            self.deu.print_log('The disk encryption is not enabled.')
            return

        self._print_caution_banner()
        proc = subprocess.Popen("sudo cryptsetup luksHeaderRestore {} --header-backup-file {}".format(
            source_device, backup_file), stderr=subprocess.PIPE, shell=True)
        _, err = proc.communicate()
        if proc.returncode != 0:
            self.deu.print_log("Failed to restore header: {}".format(err.decode("utf-8")), level=logging.ERROR)
            return
        self.deu.print_log('The header of {} is overwritten by {}.'.format(source_device, backup_file))

    def _on_disk_encrypt_info_callback(self, key, param):
        if len(param) >= 1:
            return

        target_name, source_device = self.deu.read_crypttab()
        if not target_name:
            self.deu.print_log('The disk encryption is not enabled.')
            return

        proc = subprocess.Popen("sudo cryptsetup luksDump {}".format(source_device),
                                stderr=subprocess.PIPE, shell=True)
        _, err = proc.communicate()
        if proc.returncode != 0:
            self.deu.print_log("Failed to show info: {}".format(err.decode("utf-8")), level=logging.ERROR)


def signal_handler(signal, frame):
    sys.stdout.write('^C')
    sys.stdout.flush()


def bytes2human(n):
    """
    >>> bytes2human(10000)
    '9K'
    >>> bytes2human(100001221)
    '95M'
    """
    symbols = ('K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y')
    prefix = {}
    for i, s in enumerate(symbols):
        prefix[s] = 1 << (i + 1) * 10
    for s in reversed(symbols):
        if n >= prefix[s]:
            value = int(float(n) / prefix[s])
            return '%s%s' % (value, s)
    return "%sB" % n


def main():
    signal.signal(signal.SIGINT, signal_handler)
    AellaCli().cmdloop()


if __name__ == '__main__':
    main()
