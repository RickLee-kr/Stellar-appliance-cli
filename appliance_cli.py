#!/usr/bin/env python3
"""
Copyright (c) 2026, Stellar Cyber Inc.

Appliance Command Line Interface (CLI)

Date: 2026-01-01

"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Sequence, Optional
from pathlib import Path

import datetime
import getpass
import json
import os
import os.path
import re
import sys
import cmd
import pwd
import functools

try:
    import readline
except Exception:
    readline = None

import socket
import signal
import subprocess
import shutil
import struct
import hashlib
import logging
import logging.handlers
import ipaddress
import shlex
import termios
import tempfile


MGT_CONFIG_PATH = "/etc/network/interfaces.d/01-mgt.cfg"
NETWORK_INTERFACES_PATH = "/etc/network/interfaces"
NETWORK_INTERFACES_DIR = "/etc/network/interfaces.d"
NTPSEC_CONFIG_PATH = "/etc/ntpsec/ntp.conf"
NTPSEC_SERVICE = "ntpsec"
NTPSEC_QUERY_COMMAND = ["ntpq", "-pn"]


class _AtomicCommitError(Exception):
    def __init__(self, cause, replaced):
        super().__init__(str(cause))
        self.replaced = replaced


def _prepare_atomic_text_file(path, text):
    """Fully prepare a same-directory temporary replacement for *path*."""
    path = os.fspath(path)
    directory = os.path.dirname(path) or "."
    stat_result = os.stat(path) if os.path.exists(path) else None
    fd = None
    temporary_path = None
    try:
        fd, temporary_path = tempfile.mkstemp(
            prefix=".{}.".format(os.path.basename(path)),
            dir=directory,
            text=True,
        )
        if stat_result is not None:
            os.fchmod(fd, stat_result.st_mode & 0o7777)
            try:
                os.fchown(fd, stat_result.st_uid, stat_result.st_gid)
            except PermissionError:
                current = os.fstat(fd)
                if (current.st_uid, current.st_gid) != (stat_result.st_uid, stat_result.st_gid):
                    raise
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            fd = None
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        prepared_path = temporary_path
        temporary_path = None
        return prepared_path
    finally:
        if fd is not None:
            os.close(fd)
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass


def _commit_prepared_text_file(path, temporary_path):
    """Replace *path* with a prepared file and fsync its directory."""
    path = os.fspath(path)
    directory = os.path.dirname(path) or "."
    try:
        os.replace(temporary_path, path)
    except Exception as exc:
        raise _AtomicCommitError(exc, replaced=False) from exc
    try:
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception as exc:
        raise _AtomicCommitError(exc, replaced=True) from exc


def _atomic_replace_text_file(path, text):
    """Prepare and atomically commit one text file replacement."""
    temporary_path = None
    try:
        temporary_path = _prepare_atomic_text_file(path, text)
        _commit_prepared_text_file(path, temporary_path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass

# Timezone constants
try:
    from zoneinfo import available_timezones
    ALL_TIMEZONES = frozenset(available_timezones())
except Exception:
    ALL_TIMEZONES = frozenset()

# Logging utilities
LOG_DIR = "/var/log/aella"
ACL_STAGING_PATH = "/var/lib/aella/acl_staging.json"
ACL_STATE_PATH = "/var/lib/aella/acl_state.json"
ACL_COMMENT_PREFIX = "AELLA_ACL "
ACL_AUTO_COMMENT = "AELLA_ACL_AUTO Current SSH session"
LOCAL_ALWAYS_ALLOW_COMMENT = "AELLA_LOCAL_ALWAYS_ALLOW"
ALWAYS_ALLOW_DEST_IPS = ["127.0.0.1", "192.168.0.100", "192.168.122.1"]
AELLA_INPUT_CHAIN = "AELLA_INPUT"
AELLA_SYSTEM_ALLOW_ESTABLISHED_COMMENT = "AELLA_SYSTEM Allow established"
AELLA_SYSTEM_JUMP_COMMENT = "AELLA_SYSTEM Jump to AELLA_INPUT"
AELLA_DEFAULT_WHITELIST_COMMENT = "AELLA_DEFAULT Whitelist deny all"
AELLA_DEFAULT_BLACKLIST_COMMENT = "AELLA_DEFAULT Blacklist allow all"
ACL_EXCLUDE_IPS = ("192.168.0.100", "192.168.122.1")
ACL_EXCLUDE_IP = ACL_EXCLUDE_IPS[0]


def get_username():
    return pwd.getpwuid(os.getuid())[0]


def print_log(msg: str, logger: logging.Logger | None = None, level: int = logging.INFO) -> None:
    print(msg)
    if logger:
        logger.log(level, msg)


def make_dir(target_dir, group=None, logger=None, root=False):
    target_path = Path(target_dir)
    try:
        if root:
            proc = subprocess.run(
                ["sudo", "mkdir", "-p", str(target_path)],
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        else:
            target_path.mkdir(parents=True, exist_ok=True)
            proc = subprocess.CompletedProcess([], 0, "", "")
    except PermissionError:
        proc = subprocess.run(
            ["sudo", "mkdir", "-p", str(target_path)],
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except Exception as e:
        err_msg = str(e)
        print_log("Failed to create directory {}: {}".format(target_dir, err_msg), logger, level=logging.ERROR)
        return False
    
    if proc.returncode != 0:
        err_msg = proc.stderr
        if "Permission denied" in err_msg:
            user = get_username()
            if group is None:
                group = user  # use same group as user
            proc2 = subprocess.run(
                ["sudo", "usermod", "-a", "-G", group, user],
                check=False,
            )
            if proc2.returncode != 0:
                print_log("Failed to add {} into {} group".format(user, group), logger, level=logging.ERROR)
                return False
        else:
            print_log("Failed to create directory {}: {}".format(target_dir, err_msg), logger, level=logging.ERROR)
            return False
    return True


def ensure_file(file_path, root=False, owner=None):
    if owner is None:
        owner = get_username()
    base_dir = os.path.dirname(file_path)
    if not make_dir(base_dir, root=root):
        print_log("Failed to create directory {}".format(base_dir), level=logging.ERROR)
        return False
    file_path_obj = Path(file_path)
    try:
        if root:
            proc = subprocess.run(
                ["sudo", "touch", str(file_path_obj)],
                check=False,
            )
        else:
            file_path_obj.touch(exist_ok=True)
            proc = subprocess.CompletedProcess([], 0, "", "")
    except PermissionError:
        proc = subprocess.run(
            ["sudo", "touch", str(file_path_obj)],
            check=False,
        )
    except Exception:
        proc = subprocess.run(
            ["sudo", "touch", str(file_path_obj)],
            check=False,
        )
    
    if proc.returncode != 0:
        print_log("Failed to create file {}".format(file_path), level=logging.ERROR)
        return False
    if owner != "root":
        chown_cmd = ["chown", owner, str(file_path_obj)]
        if root:
            chown_cmd = ["sudo"] + chown_cmd
        proc = subprocess.run(chown_cmd, check=False)
        if proc.returncode != 0:
            print_log("Failed to change owner of file {}".format(file_path), level=logging.ERROR)
            return False
    return True


class RotatingFileHandler(logging.handlers.RotatingFileHandler):
    def __init__(self, filename, *args, **kwargs):
        make_dir(os.path.dirname(filename), group="syslog")
        super(RotatingFileHandler, self).__init__(filename, *args, **kwargs)


def get_logger(log_name):
    filename = os.path.join(LOG_DIR, "{}.log".format(log_name))
    logger = logging.getLogger(log_name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "%(asctime)-15s|%(levelname)s|%(thread)d|%(module)s|%(message)s"
    )
    handler = RotatingFileHandler(
        filename,
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


LOG = get_logger("aella_cli")


def log_cmd(f):
    @functools.wraps(f)
    def wrapper(*args, **kwds):
        LOG.info('Run command: %s %s', f.__name__[3:], " ".join(args[1:]))
        return f(*args, **kwds)
    return wrapper

META_USER = "AellaMeta"

META_TOKEN = "WroTQfm/W6x10"

PATCH_DIR = "/home/stellar/hotfix"
PATCH_LOG_DIR = "{}/logs".format(PATCH_DIR)
PATCH_HISTORY = "{}/hotfix-history".format(PATCH_DIR)


@dataclass(frozen=True)
class CmdResult:
    args: Sequence[str]
    returncode: int
    stdout: str
    stderr: str


def run_cmd(args: Sequence[str], *, check: bool = True, timeout: Optional[int] = None) -> CmdResult:
    proc = subprocess.run(
        list(args),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=timeout,
    )
    if check and proc.returncode != 0:
        raise subprocess.CalledProcessError(
            proc.returncode, list(args),
            output=proc.stdout, stderr=proc.stderr
        )
    return CmdResult(
        args=list(args),
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
    )


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

        # Root command help
        self.root_command_help = {
            'console': 'Jump to dl-master, da-master(aka dr-master), mds, or aio console',
            'show': 'Display Component Information',
            'set': 'Configure Component Parameters',
            'unset': 'Unset Configuration',
            'shutdown': 'Shutdown System or Service',
            'start': 'Start System or Service',
            'restart': 'Restart System or Service',
            'clear': 'Clear History',
            'monitor': 'Monitor VM resources and system health',
            'quit': 'Exit CLI',
            'help': 'Display Help Information',
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
            'acl': 'Show Access Control List (iptables rules)',
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
            'acl': self.show_acl_callback,
        }

        # Set command help
        self.set_command_help = {
            'password': 'Configure Admin Password',
            'timezone': 'Configure System Timezone',
            'time': 'Configure System Time',
            'ntp': 'Configure NTP Server',
            'interface': 'Configure Interface Parameters',
            'dns': 'Configure DNS Server for Interface',
            'hostname': 'Configure Host Name',
            'patches': 'Apply patches/update',
            'autostart': 'Configure VM Auto Start',
            'acl': 'Configure Access Control List (iptables rules)',
        }

        # Set command callback
        self.set_command_callback = {
            'password': self.set_password_callback,
            'timezone': self.set_tz_callback,
            'time': self.set_time_callback,
            'ntp': self.set_ntp_callback,
            'interface': self.set_interface_callback,
            'dns': self.set_dns_callback,
            'hostname': self.set_hostname_callback,
            'patches': self.set_patches_callback,
            'patch': self.set_patches_callback,
            'autostart': self.set_autostart_callback,
            'acl': self.set_acl_callback,
        }

        self.unset_command_help = {
            'ntp': 'Unset NTP Server',
            'interface': 'Unset interface configuration',
            'acl': 'Unset Access Control List (iptables rules)'
        }

        self.unset_command_callback = {
            'ntp': self.unset_ntp_callback,
            'interface': self.unset_interface_callback,
            'acl': self.unset_acl_callback
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
            self.console_command_help[vm] = 'Go to {} console'.format(vm)
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
            'system': 'Check system health status',
        }

        self.monitor_command_callback = {
            'vm': self.monitor_vm_callback,
            'system': self.monitor_system_callback,
        }

        # Shell command
        self.shell_command = [
            'ping', 'tcpdump', 'traceroute', 'ifconfig', 'iptables', 'dmesg', 'ip', 'dig', 'htop', 'top'
        ]
        self.shell_pass = '0238b57cd42b4aa6b85991ea28702133'

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
            rc = run_cmd(["virsh", "dominfo", "da-master"], check=False).returncode
            return "da-master" if rc == 0 else "dr-master"
        except Exception:
            return 'dr-master'

    @staticmethod
    def get_vm_list():
        """Get list of all VMs from virsh list --all"""
        vm_list = []
        try:
            result = run_cmd(["virsh", "list", "--all", "--name"], check=False)
            if result.stdout:
                vm_list = [vm.strip() for vm in result.stdout.split('\n') if vm.strip()]
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
        """Display help information for commands"""
        if not line or line.strip() == '':
            # Show main help menu
            print('')
            print('Available Commands:')
            print('=' * 70)
            for cmd in sorted(self.root_command_help.keys()):
                if cmd != 'help':  # Don't show help command in the list
                    print('{0:15} {1}'.format(cmd, self.root_command_help[cmd]))
            print('')
            print('To get help for a specific command: help <command>')
            print('To get help for nested commands (show, set): <command> help')
            print('To run system commands directly: !<command> (e.g., !ping)')
            print('')
        else:
            # Show help for specific command
            cmd_name = line.strip().split()[0]
            if cmd_name in self.root_command_help:
                print('')
                print('Command: {}'.format(cmd_name))
                print('Description: {}'.format(self.root_command_help[cmd_name]))
                print('')
                # Show nested command help if available
                if cmd_name == 'show' and hasattr(self, 'show_command_help'):
                    print('Available sub-commands:')
                    for sub_cmd in sorted(self.show_command_help.keys()):
                        print('  {0:15} {1}'.format(sub_cmd, self.show_command_help[sub_cmd]))
                    print('')
                    print('Usage: show <sub-command>')
                elif cmd_name == 'set' and hasattr(self, 'set_command_help'):
                    print('Available sub-commands:')
                    for sub_cmd in sorted(self.set_command_help.keys()):
                        print('  {0:15} {1}'.format(sub_cmd, self.set_command_help[sub_cmd]))
                    print('')
                    print('Usage: set <sub-command> [parameters]')
                elif cmd_name == 'unset' and hasattr(self, 'unset_command_help'):
                    print('Available sub-commands:')
                    for sub_cmd in sorted(self.unset_command_help.keys()):
                        print('  {0:15} {1}'.format(sub_cmd, self.unset_command_help[sub_cmd]))
                    print('')
                    print('Usage: unset <sub-command>')
                elif cmd_name in ['start', 'restart', 'shutdown']:
                    if hasattr(self, '{}_command_help'.format(cmd_name)):
                        help_dict = getattr(self, '{}_command_help'.format(cmd_name))
                        if help_dict:
                            print('Available options:')
                            for sub_cmd in sorted(help_dict.keys()):
                                print('  {0:15} {1}'.format(sub_cmd, help_dict[sub_cmd]))
                            print('')
                            print('Usage: {} <option>'.format(cmd_name))
                elif cmd_name == 'console':
                    if hasattr(self, 'console_command_help'):
                        if self.console_command_help:
                            print('Available console options:')
                            for sub_cmd in sorted(self.console_command_help.keys()):
                                print('  {0:15} {1}'.format(sub_cmd, self.console_command_help[sub_cmd]))
                            print('')
                            print('Usage: console <vm-name>')
                        else:
                            print('No VMs available for console access.')
                            print('')
                elif cmd_name == 'monitor':
                    print('Usage: monitor')
                    print('Displays VM resources and system health information.')
                    print('')
            else:
                print('')
                print("Unknown command: '{}'".format(cmd_name))
                print('Type "help" to see available commands.')
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
                subprocess.call("/usr/bin/sudo bash -lc 'cd /root && exec bash'", shell=True)
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
            self.shell_cmd_exec('virsh shutdown {}'.format(vm_name))
        return callback

    def _reset_console_terminal(self, saved_attrs=None):
        fd = sys.stdin.fileno()
        if saved_attrs is not None:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, saved_attrs)
            except (termios.error, OSError, ValueError):
                pass
        try:
            with open("/dev/tty", "r") as tty:
                subprocess.call(["stty", "sane"], stdin=tty, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        except OSError:
            pass

    def _attach_vm_console(self, vm_name):
        """Attach to a VM serial/virtio console with proper TTY handoff."""
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            print("\nConsole requires an interactive terminal.\n")
            return

        state = run_cmd(["virsh", "domstate", vm_name], check=False).stdout.strip()
        if state != "running":
            print("\nVM {} is not running (state: {}).\n".format(vm_name, state or "unknown"))
            return

        fd = sys.stdin.fileno()
        saved_attrs = None
        try:
            saved_attrs = termios.tcgetattr(fd)
        except (termios.error, OSError, ValueError):
            pass

        self._reset_console_terminal(saved_attrs)
        print("\nConnecting to {} console (Escape character is ^] )...\n".format(vm_name))
        rc = subprocess.call(["virsh", "console", "--force", vm_name])
        self._reset_console_terminal(saved_attrs)

        if rc != 0:
            print(
                "\nConsole disconnected from {}.\n"
                "This is normal if the guest rebooted or closed the console during bootstrap.\n"
                "Reconnect with: console {}\n".format(vm_name, vm_name)
            )
        else:
            print("")

    def _create_vm_console_callback(self, vm_name):
        """Create a callback function for console access to a VM"""
        def callback(key, param):
            self._attach_vm_console(vm_name)
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
        elif line.startswith('show interface'):
            return self.complete_show_interface(text, line, begidx, endidx)
        else:
            completions = [f for f in self.show_command_help.keys() if f.startswith(text)]
        return completions

    # Need to use timedatectl to get the timezone for both Ubuntu 16.04 and 24.04
    def show_tz_callback(self, key, param):
        try:
            result = subprocess.check_output(
                ["timedatectl", "show", "-p", "Timezone", "--value"],
                stderr=subprocess.PIPE
            ).decode("utf-8").strip()
            if result:
                print("Timezone: {}".format(result))
            else:
                print("Timezone: (unknown)")
        except subprocess.CalledProcessError:
            print("Failed to retrieve timezone using timedatectl")

    def show_time_callback(self, key, param):
        self.shell_cmd_exec('date \"+%a %Y-%m-%d %H:%M:%S %Z\"')

    def _list_timezones(self) -> list[str]:
        try:
            out = subprocess.check_output(
                ["timedatectl", "list-timezones"],
                stderr=subprocess.PIPE
            ).decode().splitlines()
            timezones = [x.strip() for x in out if x.strip()]
            if timezones:
                return sorted(timezones)
        except Exception:
            pass
        if ALL_TIMEZONES:
            return sorted(ALL_TIMEZONES)
        return []

    _NTPSEC_BLOCK_BEGIN_TAGS = frozenset({
        "# === XDR_NTPSEC_CONFIG_BEGIN ===",
        "# XDR_NTPSEC_CONFIG_BEGIN",
    })
    _NTPSEC_BLOCK_END_TAGS = frozenset({
        "# === XDR_NTPSEC_CONFIG_END ===",
        "# XDR_NTPSEC_CONFIG_END",
    })
    _NTPSEC_MARKER_PAIRS = {
        "# === XDR_NTPSEC_CONFIG_BEGIN ===": "# === XDR_NTPSEC_CONFIG_END ===",
        "# XDR_NTPSEC_CONFIG_BEGIN": "# XDR_NTPSEC_CONFIG_END",
    }

    @staticmethod
    def _strip_ntp_conf_line(line):
        return line.replace('\r', '').strip()

    @classmethod
    def _is_ntpsec_block_begin(cls, line):
        return cls._strip_ntp_conf_line(line) in cls._NTPSEC_BLOCK_BEGIN_TAGS

    @classmethod
    def _is_ntpsec_block_end(cls, line):
        return cls._strip_ntp_conf_line(line) in cls._NTPSEC_BLOCK_END_TAGS

    def _parse_ntpsec_managed_block(self, lines, allow_absent=False):
        begins = [
            (index, self._strip_ntp_conf_line(line))
            for index, line in enumerate(lines) if self._is_ntpsec_block_begin(line)
        ]
        ends = [
            (index, self._strip_ntp_conf_line(line))
            for index, line in enumerate(lines) if self._is_ntpsec_block_end(line)
        ]
        if not begins and not ends:
            if allow_absent:
                return None, None
            raise ValueError("NTPsec managed block not found")
        if len(begins) != 1 or len(ends) != 1:
            raise ValueError("Malformed NTPsec managed block markers")
        start, begin_tag = begins[0]
        end, end_tag = ends[0]
        if end <= start or self._NTPSEC_MARKER_PAIRS[begin_tag] != end_tag:
            raise ValueError("Malformed NTPsec managed block markers")
        return start, end

    def _render_ntpsec_change(self, original, action, targets):
        lines = original.splitlines(keepends=True)
        start, end = self._parse_ntpsec_managed_block(lines)
        normalized = []
        for target in targets:
            target = self._normalize_ntp_target(target)
            if target and target not in normalized:
                normalized.append(target)
        all_targets = set()
        for line in lines[start + 1:end]:
            stripped = self._strip_ntp_conf_line(line)
            if not stripped or stripped.startswith("#"):
                continue
            match = re.match(r"^(server|pool)\s+(\S+)", stripped)
            if match:
                all_targets.add(match.group(2))
        newline = "\r\n" if "\r\n" in original else "\n"

        if action == "add":
            additions = [target for target in normalized if target not in all_targets]
            if not additions:
                return original, False
            peer_lines = ["server {} iburst{}".format(target, newline) for target in additions]
            lines[end:end] = peer_lines
            return "".join(lines), True

        block = lines[start + 1:end]
        if action == "unset":
            target_set = set(normalized)
            changed = False
            kept = []
            for line in block:
                match = re.match(r"^\s*(server|pool)\s+(\S+)", line)
                if match and match.group(2) in target_set:
                    changed = True
                    continue
                kept.append(line)
            if not changed:
                return original, False
            lines[start + 1:end] = kept
            return "".join(lines), True

        # replace: preserve every non-peer line in the managed block.
        kept = []
        insert_at = None
        for line in block:
            if re.match(r"^\s*(server|pool)\s+\S+", line):
                if insert_at is None:
                    insert_at = len(kept)
                continue
            kept.append(line)
        if insert_at is None:
            insert_at = len(kept)
        kept[insert_at:insert_at] = [
            "server {} iburst{}".format(target, newline) for target in normalized
        ]
        lines[start + 1:end] = kept
        rendered = "".join(lines)
        return rendered, rendered != original

    def _commit_ntpsec_text(self, original, updated):
        if updated == original:
            return False
        try:
            _atomic_replace_text_file(NTPSEC_CONFIG_PATH, updated)
        except Exception as exc:
            print("Failed to update NTP configuration: {}".format(exc))
            return False
        if self._restart_ntp_service(NTPSEC_SERVICE):
            return True
        try:
            _atomic_replace_text_file(NTPSEC_CONFIG_PATH, original)
        except Exception as exc:
            print(
                "CRITICAL: Failed to restore NTP configuration: {} "
                "Manual recovery is required.".format(exc)
            )
            return False
        if not self._restart_ntp_service(NTPSEC_SERVICE):
            print(
                "NTPsec restart failed after restoring the original configuration. "
                "Run 'sudo -n systemctl restart {}' manually.".format(NTPSEC_SERVICE)
            )
        return False

    def _normalize_ntp_target(self, target_raw):
        target = target_raw.strip().replace('\r', '')
        match = re.match(r"^(server|pool)\s+(.+)$", target, re.IGNORECASE)
        if match:
            target = match.group(2).strip()
        return target

    def _is_valid_ntp_target(self, target):
        if not target:
            return False
        if self.valid_ipv4_address(target):
            return True
        if re.fullmatch(r"[\d.]+", target):
            return False
        return self.is_valid_hostname(target)

    def _parse_ntpq_output(self, output):
        peers = []
        warnings = []
        reachable = False
        for line in output.splitlines():
            line_stripped = line.strip()
            if not line_stripped or line_stripped.lower().startswith("remote") or line_stripped.startswith("="):
                continue
            tokens = line_stripped.split()
            if len(tokens) < 7:
                continue
            remote = tokens[0]
            if remote and remote[0] in "*+o#x.-?":
                remote = remote[1:]
            refid = tokens[1]
            st = tokens[2]
            reach = tokens[6]
            peers.append((remote, refid, st, reach))
            reach_int = None
            if reach.isdigit():
                try:
                    reach_int = int(reach, 8)
                except Exception:
                    reach_int = None
            if reach_int is not None and reach_int > 0:
                reachable = True
            if reach_int == 0 or st == "16" or refid == ".DNS.":
                warnings.append("warning: peer {} reach={} st={} refid={}".format(remote, reach, st, refid))
        return peers, reachable, warnings

    def _restart_ntp_service(self, service_name):
        proc = subprocess.run(
            ["sudo", "-n", "systemctl", "restart", service_name],
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            print("Failed to restart NTP service: {}".format(service_name))
            print("Check sudo NOPASSWD for: systemctl restart {}".format(service_name))
            return False
        return True

    def show_dns_callback(self, key, param):
        """Show DNS servers from the canonical management stanza only."""
        try:
            text = self._read_text_exact(MGT_CONFIG_PATH)
            lines, start, end = self._mgt_static_stanza_bounds(text)
            dns = []
            for line in lines[start + 1:end]:
                match = re.match(r"^\s*dns-nameservers\s+(.+?)(?:\r?\n)?$", line)
                if match:
                    dns.extend(match.group(1).split())
            if dns:
                output = "Management DNS servers:\n"
                output += "".join("  {}\n".format(item) for item in dns)
                output += "Configuration source:\n  {}".format(MGT_CONFIG_PATH)
            else:
                output = "No DNS servers configured for mgt"
            status = 0
        except Exception as e:
            output = "\nFailed to get DNS servers: {}\n".format(e)
            status = 1
        print(output)
        return status, output

    def show_acl_callback(self, key, param):
        """
        NEW:
          show acl

        Shows:
          - policy summary (mode/iface/iface_ip)
          - AELLA_INPUT_CHAIN rules in real order (only AELLA_ACL + default tail)
        """
        state = self._load_acl_state()
        if not state:
            output = "\nACL policy is not initialized. Run 'set acl policy' first.\n"
            print(output)
            return 1, output

        iface = state["iface"]
        try:
            iface_ip = self._get_iface_ipv4(iface)
        except Exception:
            iface_ip = "(unknown)"

        output = "\n" + "=" * 60 + "\n"
        output += "Access Control List (AELLA managed)\n"
        output += "=" * 60 + "\n"
        output += f"mode : {state['mode']}\n"
        output += f"iface: {iface}\n"
        output += f"iface_ip: {iface_ip}\n\n"

        if not self._iptables_chain_exists(AELLA_INPUT_CHAIN):
            output += "No applied ACL chain found. (No rules applied yet)\n\n"
            print(output)
            return 0, output

        rc, out, err = self._run_cmd(f"sudo iptables -S {AELLA_INPUT_CHAIN}")
        if rc != 0:
            output += "Failed to get iptables rules: {}\n\n".format(err.strip() or "Unknown error")
            print(output)
            return 1, output

        lines = out.splitlines() if out else []
        shown = 0
        for line in lines:
            if not line.startswith(f"-A {AELLA_INPUT_CHAIN}"):
                continue
            if ACL_COMMENT_PREFIX.strip() in line:
                shown += 1
                output += f"  {line}\n"
                continue
            if AELLA_DEFAULT_WHITELIST_COMMENT in line or AELLA_DEFAULT_BLACKLIST_COMMENT in line:
                shown += 1
                output += f"  {line}\n"

        if shown == 0:
            output += "  (No AELLA ACL rules found in chain)\n"
        output += "\n"
        print(output)
        return 0, output

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
        """Reject host network changes in Sensor bridge mode."""
        self._debug_print("DEBUG set interface param={}".format(param))
        param = [p for p in param if p != '']
        if not param or len(param) < 1:
            print('\n<Interface Name>  Specify an existing host interface/bridge name\n')
            return

        interface = param[0].rstrip('?')
        if param[0].endswith('?') or interface == '?':
            print('\n<Interface Name>  Specify an existing host interface/bridge name\n')
            return

        print(
            "Host IP configuration is not managed by this CLI in Sensor bridge mode.\n"
            "Configure the Sensor VM management IP inside the Sensor VM."
        )
        return


    def unset_interface_sensor(self, param):
        """Reject host network removals in Sensor bridge mode."""
        param = [p for p in param if p != ""]
        if not param or param[0].endswith("?") or param[0] == "?":
            print("\n<Interface Name>  Specify an existing host interface/bridge name\n")
            return
        print(
            "Host IP configuration is not managed by this CLI in Sensor bridge mode.\n"
            "Configure the Sensor VM management IP inside the Sensor VM."
        )

    def show_gateway_callback(self, key, param):
        try:
            text = self._read_text_exact(MGT_CONFIG_PATH)
            lines, start, end = self._mgt_static_stanza_bounds(text)
            gateway = None
            for line in lines[start + 1:end]:
                match = re.match(r"^\s*gateway\s+(\S+)", line)
                if match:
                    gateway = match.group(1)
                    break
            print("\nConfigured management gateway: {}".format(gateway or "(none)"))
            runtime = subprocess.run(
                ["ip", "-4", "route", "show", "table", "main", "default"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
            )
            if runtime.returncode == 0 and runtime.stdout.strip():
                print("Runtime main-table default: {}".format(runtime.stdout.strip()))
            print("")
        except Exception as exc:
            print("Failed to get gateway: {}".format(exc))

    def show_service(self, key, param):
        if key:
            self.shell_cmd_exec('sudo virsh list --all')

    @staticmethod
    def _parse_virsh_autostart(dominfo_text: str) -> Optional[bool]:
        for line in dominfo_text.splitlines():
            if line.lower().startswith("autostart:"):
                raw_value = line.split(":", 1)[1].strip().lower()
                if raw_value in {"enable", "enabled", "yes", "on", "1"}:
                    return True
                if raw_value in {"disable", "disabled", "no", "off", "0"}:
                    return False
                return None
        return None

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
                cmd = "virsh dominfo {} 2>/dev/null".format(vm)
                proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, err = proc.communicate()
                status = 'unknown'
                if out:
                    parsed = self._parse_virsh_autostart(out.decode('utf-8', errors='ignore'))
                    if parsed is True:
                        status = 'enabled'
                    elif parsed is False:
                        status = 'disabled'
                print('  {:<20} {}'.format(vm, status))
            except Exception:
                print('  {:<20} unknown'.format(vm))
        print('')

    def show_interface_callback(self, key, param):
        if param and param[0].rstrip("?") == "mgt":
            if param[0].endswith("?"):
                print("\nPress [Enter]\n")
                return
            self.shell_cmd_exec("sudo ifconfig mgt 2>/dev/null")
            return
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
                     print('\nPress [Enter]\n')
                     return
                #elif len(param) == 1 and (param[0] == '?' or not (param[0] == 'mgt' or param[0] == 'data1g' or param[0] == 'data10g')):
                elif len(param) == 1 and (param[0] == '?' or not re.match('mgt|data1[0]?g|cltr0', param[0])):
                    print('\n<Interface Name>  Specify a supported interface name (mgt, data1g, data10g, cltr0)')
                    print('Press [Enter]\n')
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
                     print('\nPress [Enter]\n')
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
                print('Press [Enter]\n')
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
                print('Press [Enter]\n')
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
                print('Press [Enter]\n')
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
        timezones = self._list_timezones()
        if not timezones:
            print("Failed to list timezones")
            return

        if len(param) == 0:
            regions = sorted({tz.split("/", 1)[0] if "/" in tz else tz for tz in timezones})
            print("\nAvailable regions:\n")
            for region in regions:
                print(region)
            print("\nExamples:")
            print("  set timezone Asia")
            print("  set timezone Asia/Seoul")
            print("  set timezone \"America/Los_Angeles\"\n")
            return

        tz_raw = " ".join(param).strip()
        tz = tz_raw
        if len(tz) >= 2 and tz[0] == tz[-1] and tz[0] in ("'", '"'):
            tz = tz[1:-1].strip()

        regions = {tz_item.split("/", 1)[0] if "/" in tz_item else tz_item for tz_item in timezones}

        if tz in timezones:
            proc = subprocess.run(
                ["sudo", "timedatectl", "set-timezone", tz],
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if proc.returncode != 0:
                err = proc.stderr.strip() if proc.stderr else "Unknown error"
                print("Failed to set timezone: {}".format(err))
            return

        if tz in regions and "/" not in tz:
            candidates = [t for t in timezones if t.startswith(tz + "/")]
            priority_terms = ["Seoul", "Tokyo", "New_York", "Los_Angeles"]

            def _tz_sort_key(value: str) -> tuple[int, str]:
                for term in priority_terms:
                    if term in value:
                        return (0, value)
                return (1, value)

            candidates = sorted(candidates, key=_tz_sort_key)
            limit = 50
            print("\nAvailable timezones for {}:\n".format(tz))
            for item in candidates[:limit]:
                print(item)
            remaining = len(candidates) - limit
            if remaining > 0:
                print("... ({} more)".format(remaining))
            print("\nPick one: set timezone <Region/City>\n")
            return

        print("Unknown timezone: {}".format(tz))
        print("Unknown timezone. e.g.: 'America/Los_Angeles'")
        print("Try: set timezone <Region>  (to list options)")
        suggestions = []
        for item in timezones:
            if item.startswith(tz):
                suggestions.append(item)
        for item in timezones:
            if tz in item and item not in suggestions:
                suggestions.append(item)
        if suggestions:
            print("Suggestions:")
            for item in suggestions[:5]:
                print("  {}".format(item))
        return

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

    def _detect_ntp_type(self):
        """Validate that the supported NTPsec backend is usable."""
        error = "NTPsec is not installed or /etc/ntpsec/ntp.conf is missing."
        if not os.path.isfile(NTPSEC_CONFIG_PATH):
            raise RuntimeError(error)
        service = subprocess.run(
            ["systemctl", "cat", NTPSEC_SERVICE],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
        )
        if service.returncode != 0:
            raise RuntimeError(error)
        if not shutil.which(NTPSEC_QUERY_COMMAND[0]):
            raise RuntimeError(error)
        query = subprocess.run(
            NTPSEC_QUERY_COMMAND,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
        )
        if query.returncode not in (0, 1):
            raise RuntimeError(error)
        return "ntpsec", NTPSEC_CONFIG_PATH, NTPSEC_SERVICE

    def set_dns_callback(self, key, param):
        """Configure DNS servers for a network interface"""
        if not param or param[0].endswith('?') or len(param) < 2:
            print('\n<Interface Name> <DNS IP> [...]  Specify interface name and DNS server IP address(es)\n')
            print('Example: set dns mgt 8.8.8.8 8.8.4.4\n')
            return
        
        interface = param[0].rstrip('?')
        if param[0].endswith('?') or interface == '?':
            print('\n<Interface Name> <DNS IP> [...]  Specify interface name and DNS server IP address(es)\n')
            return
        if interface != "mgt":
            print('Invalid option: Only "mgt" interface supports DNS configuration')
            return
        
        # Validate DNS IP addresses
        dns_servers = param[1:]
        for dns in dns_servers:
            if not self.valid_ipv4_address(dns):
                print('Invalid DNS server IP address format: {}\n'.format(dns))
                return
        
        if self._update_mgt_ipv4_config(dns_servers=dns_servers):
            if self._mgt_last_changed:
                print("Configuration updated successfully.")
                print("Run 'set interface mgt restart' to apply the changes.")

    def _ntpsec_operation(self, action, targets):
        try:
            self._detect_ntp_type()
            original = self._read_text_exact(NTPSEC_CONFIG_PATH)
            updated, changed = self._render_ntpsec_change(original, action, targets)
        except Exception as exc:
            print("Failed to update NTP configuration: {}".format(exc))
            return False
        if not changed:
            if action == "unset":
                print("NTP server not found in CLI-managed block")
            else:
                print("NTP configuration is unchanged")
            return False
        if not self._commit_ntpsec_text(original, updated):
            return False
        query = subprocess.run(
            NTPSEC_QUERY_COMMAND,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
        )
        if query.returncode == 0:
            peers, _, _ = self._parse_ntpq_output(query.stdout)
            reach_zero = False
            for peer in peers:
                try:
                    if int(peer[3], 8) == 0:
                        reach_zero = True
                        break
                except (TypeError, ValueError):
                    continue
            if reach_zero:
                print("Warning: NTP peers currently have reach=0")
        return True

    def set_ntp_callback(self, key, param):
        if not param or param[0].endswith("?"):
            print("\n<NTP server> \t Specify NTP server name or IP address\n")
            return
        action = "add"
        targets = list(param)
        if param[0] in ("add", "replace"):
            action = param[0]
            targets = param[1:]
        if not targets:
            print("\n<NTP server> \t Specify NTP server name or IP address\n")
            return
        targets = [self._normalize_ntp_target(target) for target in targets]
        if any(not self._is_valid_ntp_target(target) for target in targets):
            print("Invalid NTP hostname: Please enter the correct hostname")
            return
        if self._ntpsec_operation(action, targets):
            if action == "replace":
                print("Successfully replaced ntp servers\n")
            else:
                print("Successfully set ntp servers\n")
            return 0
        return 1

    def show_ntp_callback(self, key, param):
        try:
            self._detect_ntp_type()
            lines = self._read_text_exact(NTPSEC_CONFIG_PATH).splitlines(keepends=True)
            start, end = self._parse_ntpsec_managed_block(lines)
            entries = []
            if start is not None:
                for line in lines[start + 1:end]:
                    match = re.match(r"^\s*(server|pool)\s+(\S+)", line)
                    if match:
                        entries.append("{} {}".format(match.group(1), match.group(2)))
            active = subprocess.run(
                ["systemctl", "is-active", NTPSEC_SERVICE],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
            )
            enabled = subprocess.run(
                ["systemctl", "is-enabled", NTPSEC_SERVICE],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
            )
            query = subprocess.run(
                NTPSEC_QUERY_COMMAND,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
            )
            output = "\n[configured NTP servers - CLI managed]\n"
            output += "".join("- {}\n".format(entry) for entry in entries) or "(none)\n"
            output += "\n[service]\n- {}: {} ({})\n".format(
                NTPSEC_SERVICE,
                active.stdout.strip() if active.returncode == 0 else "inactive",
                enabled.stdout.strip() if enabled.returncode == 0 else "disabled",
            )
            output += "\n[runtime sync status]\n"
            output += query.stdout if query.returncode == 0 else "(ntpq query failed)\n"
            print(output)
            return 0, output
        except Exception as exc:
            output = "Failed to get ntp servers: {}\n".format(exc)
            print(output)
            return 1, output

    def _get_local_interface_ips(self):
        """Return only the approved always-allow destination IPs"""
        return list(ALWAYS_ALLOW_DEST_IPS)

    def get_ipv4_addrs(self, iface: str) -> list[str]:
        """Return IPv4 addresses for an interface"""
        cmd = ["ip", "-4", "-o", "addr", "show", "dev", iface]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        if proc.returncode != 0 or not proc.stdout:
            return []
        addrs = []
        for line in proc.stdout.splitlines():
            match = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/", line)
            if match:
                addrs.append(match.group(1))
        return addrs

    def list_candidate_ifaces(self, exclude_ips: Sequence[str] = ACL_EXCLUDE_IPS) -> list[dict]:
        """Return candidate interfaces with IPv4 list, excluding any in ACL_EXCLUDE_IPS"""
        if isinstance(exclude_ips, str):
            exclude_set = {exclude_ips}
        else:
            exclude_set = set(exclude_ips)
        candidates = []
        for iface in self.list_host_nics():
            ipv4s = self.get_ipv4_addrs(iface)
            if not ipv4s:
                continue
            if exclude_set.intersection(ipv4s):
                continue
            candidates.append({"iface": iface, "ipv4": ipv4s})
        return candidates

    def _load_acl_state(self) -> dict:
        """Load ACL policy state"""
        default_data = {"mode": None, "iface": None, "exclude_ip": list(ACL_EXCLUDE_IPS)}
        try:
            with open(ACL_STATE_PATH, "r") as f:
                data = json.load(f)
        except FileNotFoundError:
            return default_data
        except PermissionError:
            proc = subprocess.run(
                ["sudo", "cat", ACL_STATE_PATH],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if proc.returncode != 0 or not proc.stdout:
                return default_data
            try:
                data = json.loads(proc.stdout)
            except json.JSONDecodeError:
                return default_data
        except json.JSONDecodeError:
            return default_data
        except Exception:
            return default_data

        if not isinstance(data, dict):
            return default_data
        if "mode" not in data or "iface" not in data:
            return default_data
        if "exclude_ip" not in data:
            data["exclude_ip"] = list(ACL_EXCLUDE_IPS)
        return data

    def load_acl_state(self) -> dict:
        return self._load_acl_state()

    def _save_acl_state(self, data: dict) -> None:
        """Save ACL policy state"""
        target_dir = os.path.dirname(ACL_STATE_PATH)
        make_dir(target_dir, root=True)
        payload = json.dumps(data, indent=2, sort_keys=False)
        tmp_path = "/tmp/acl_state.json"
        try:
            with open(tmp_path, "w") as f:
                f.write(payload)
            subprocess.run(
                ["sudo", "mv", tmp_path, ACL_STATE_PATH],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        except Exception:
            try:
                subprocess.run(
                    ["sudo", "tee", ACL_STATE_PATH],
                    input=payload,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
            except Exception:
                pass

    def save_acl_state(self, data: dict) -> None:
        self._save_acl_state(data)

    def _run_whiptail_radiolist(self, title: str, text: str, items: list[tuple[str, str, bool]]) -> Optional[str]:
        args = ["whiptail", "--title", title, "--radiolist", text, "20", "78", str(len(items))]
        for tag, desc, on in items:
            args.extend([tag, desc, "ON" if on else "OFF"])
        try:
            proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        except FileNotFoundError:
            return self._prompt_radiolist(title, text, items)
        if proc.returncode != 0:
            return None
        if not proc.stdout:
            return self._prompt_radiolist(title, text, items)
        return proc.stdout.strip()

    def _run_whiptail_yesno(self, title: str, text: str) -> bool:
        args = ["whiptail", "--title", title, "--yesno", text, "20", "78"]
        try:
            proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        except FileNotFoundError:
            return self._prompt_yesno(title, text)
        return proc.returncode == 0

    def _prompt_yesno(self, title: str, text: str) -> bool:
        print("\n{}:".format(title))
        print(text)
        while True:
            choice = input("Type 'yes' to continue or 'no' to cancel: ").strip().lower()
            if choice in ("yes", "y"):
                return True
            if choice in ("no", "n"):
                return False
            print("Please enter yes or no.")

    def _prompt_radiolist(self, title: str, text: str, items: list[tuple[str, str, bool]]) -> Optional[str]:
        print("\n{}:".format(title))
        print(text)
        for idx, (tag, desc, _on) in enumerate(items, start=1):
            print("  {}) {} - {}".format(idx, tag, desc))
        while True:
            choice = input("Select number (or press Enter to cancel): ").strip()
            if choice == "":
                return None
            if not choice.isdigit():
                print("Please enter a valid number.")
                continue
            index = int(choice)
            if 1 <= index <= len(items):
                return items[index - 1][0]
            print("Please enter a valid number.")

    def _is_iface_candidate(self, iface: str, exclude_ips: Sequence[str]) -> bool:
        candidates = self.list_candidate_ifaces(exclude_ips=exclude_ips)
        return any(item["iface"] == iface for item in candidates)

    def _print_acl_help(self, policy_configured: bool) -> None:
        print("ACL policy is not initialized.")
        print("You must run 'set acl policy' before adding or applying any ACL rules.\n")
        print('------------------------------------------------------------')
        print('Required first step:')
        print('  set acl policy        Initialize ACL mode (whitelist/blacklist) and target interface\n')
        print('------------------------------------------------------------')
        print('ACL rule syntax (available after policy is initialized):')
        print('  set acl <IP/network> <port|icmp|ping|all> [description]\n')
        print('  IP/network : IP address (e.g., 192.168.1.100) or network (e.g., 192.168.1.0/24)')
        print('  port       : Port number (e.g., 22, 80, 443), "icmp"/"ping", or "all" for all ports')
        print('               Multiple ports can be specified separated by space')
        print('  description: Optional description/comment\n')
        print('------------------------------------------------------------')
        print('Apply staged rules (rules must exist):')
        print('  set acl apply          Apply staged ACL rules (merge)')
        print('  set acl apply --reset  Reset applied ACL rules and rebuild from staging\n')
        print('------------------------------------------------------------')
        print('Examples:')
        print('  set acl policy')
        print('  set acl 192.168.1.100 22 "Admin SSH access"')
        print('  set acl 192.168.1.0/24 80 443 "Web servers"')
        print('  set acl 10.0.0.0/8 all "Internal network"')
        print('  set acl apply\n')

    def _print_acl_policy_warning_only(self) -> None:
        print("ACL policy is not configured. Run: set acl policy\n")

    def _delete_acl_state_file(self) -> None:
        try:
            subprocess.run(["sudo", "rm", "-f", ACL_STATE_PATH], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        except Exception:
            pass

    def _clear_aella_managed_rules(self) -> None:
        lines = self._read_chain_rule_lines("INPUT")
        for line in lines:
            if AELLA_SYSTEM_ALLOW_ESTABLISHED_COMMENT in line or "-j {}".format(AELLA_INPUT_CHAIN) in line:
                self._delete_chain_rule_line(line)

        if subprocess.run(["sudo", "iptables", "-S", AELLA_INPUT_CHAIN], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False).returncode == 0:
            _, chain_rules = self.parse_chain_rules(AELLA_INPUT_CHAIN)
            for rule in chain_rules:
                if "AELLA_DEFAULT" in (rule.get("comment") or "") or self._comment_is_user_acl(rule.get("comment")):
                    self._delete_chain_rule_line(rule["raw"])
            subprocess.run(["sudo", "iptables", "-F", AELLA_INPUT_CHAIN], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            subprocess.run(["sudo", "iptables", "-X", AELLA_INPUT_CHAIN], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)

    def _run_policy_wizard(self) -> Optional[dict]:
        exclude_ips = ACL_EXCLUDE_IPS
        candidates = self.list_candidate_ifaces(exclude_ips=exclude_ips)
        if not candidates:
            print("ACL 적용 가능한 IPv4 인터페이스가 없습니다.\n")
            return None

        mode_text = (
            "Select ACL mode.\n\n"
            "Whitelist: only the rules you enter are allowed, everything else is dropped (DROP). "
            "You must allow your SSH management IP.\n"
            "Blacklist: only the rules you enter are dropped (DROP), everything else is allowed (ACCEPT)."
        )
        mode = self._run_whiptail_radiolist(
            "ACL Mode",
            mode_text,
            [
                ("whitelist", "Allow only listed rules (default deny)", True),
                ("blacklist", "Deny only listed rules (default allow)", False),
            ],
        )
        if not mode:
            return None

        iface_items = []
        for i, item in enumerate(candidates):
            iface = item["iface"]
            ips = ", ".join(item["ipv4"])
            iface_items.append((iface, "IPv4: {}".format(ips), i == 0))
        iface = self._run_whiptail_radiolist("ACL Interface", "Select a single interface for ACL.", iface_items)
        if not iface:
            return None

        return {"mode": mode, "iface": iface, "exclude_ip": list(exclude_ips)}

    def configure_acl_policy(self) -> bool:
        warning_text = (
            "WARNING: Re-initializing ACL policy will DELETE ALL existing ACL rules (staged and applied).\n"
            "This action cannot be undone. Continue?"
        )
        if not self._run_whiptail_yesno("ACL Policy", warning_text):
            return False

        self._delete_acl_state_file()
        self._clear_acl_staging()
        self._clear_aella_managed_rules()

        state = self._run_policy_wizard()
        if not state:
            return False

        self._save_acl_state(state)
        print("Policy is configured. No firewall rules are active until at least one ACL rule is added and 'set acl apply' is executed.\n")
        return True

    def get_current_ssh_client_ip(self) -> Optional[str]:
        """Get current SSH client IPv4 address if available"""
        env_val = os.environ.get("SSH_CONNECTION")
        if env_val:
            tokens = env_val.strip().split()
            candidate = tokens[0] if tokens else None
            if candidate and self.valid_ipv4_address(candidate):
                return candidate
        env_val = os.environ.get("SSH_CLIENT")
        if env_val:
            tokens = env_val.strip().split()
            candidate = tokens[0] if tokens else None
            if candidate and self.valid_ipv4_address(candidate):
                return candidate
        return None

    def _run_iptables(self, args: list[str], error_prefix: str) -> str:
        proc = subprocess.run(["sudo", "iptables"] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        if proc.returncode != 0:
            err_msg = proc.stderr.strip() if proc.stderr else "Unknown error"
            raise RuntimeError("{}: {}".format(error_prefix, err_msg))
        return proc.stdout or ""

    def _read_chain_rule_lines(self, chain: str) -> list[str]:
        proc = subprocess.run(["sudo", "iptables", "-S", chain], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        if proc.returncode != 0:
            return []
        return [line for line in proc.stdout.splitlines() if line.startswith("-A ")]

    def _delete_chain_rule_line(self, line: str) -> None:
        tokens = shlex.split(line)
        if not tokens or tokens[0] != "-A":
            return
        tokens[0] = "-D"
        self._run_iptables(tokens, "Failed to delete iptables rule")

    def parse_chain_rules(self, chain: str) -> tuple[list[str], list[dict]]:
        lines = self._read_chain_rule_lines(chain)
        rules = []
        for line in lines:
            tokens = shlex.split(line)
            rule = {
                "raw": line,
                "src": None,
                "proto": None,
                "dport": None,
                "target": None,
                "comment": None,
            }
            i = 0
            while i < len(tokens):
                tok = tokens[i]
                if tok == "-s" and i + 1 < len(tokens):
                    rule["src"] = tokens[i + 1]
                    i += 2
                    continue
                if tok == "-p" and i + 1 < len(tokens):
                    rule["proto"] = tokens[i + 1]
                    i += 2
                    continue
                if tok == "--dport" and i + 1 < len(tokens):
                    rule["dport"] = tokens[i + 1]
                    i += 2
                    continue
                if tok == "-j" and i + 1 < len(tokens):
                    rule["target"] = tokens[i + 1]
                    i += 2
                    continue
                if tok == "--comment" and i + 1 < len(tokens):
                    rule["comment"] = tokens[i + 1]
                    i += 2
                    continue
                i += 1
            rules.append(rule)
        return lines, rules

    def ensure_aella_chain(self) -> None:
        proc = subprocess.run(["sudo", "iptables", "-S", AELLA_INPUT_CHAIN], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        if proc.returncode == 0:
            return
        self._run_iptables(["-N", AELLA_INPUT_CHAIN], "Failed to create AELLA_INPUT chain")

    def ensure_established_rule(self) -> None:
        lines = self._read_chain_rule_lines("INPUT")
        for line in lines:
            if AELLA_SYSTEM_ALLOW_ESTABLISHED_COMMENT in line:
                self._delete_chain_rule_line(line)
        self._run_iptables(
            [
                "-I",
                "INPUT",
                "1",
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
                "-m",
                "comment",
                "--comment",
                AELLA_SYSTEM_ALLOW_ESTABLISHED_COMMENT,
            ],
            "Failed to ensure established/related rule",
        )

    def ensure_jump_rule(self, iface: str) -> None:
        lines = self._read_chain_rule_lines("INPUT")
        for line in lines:
            if "-j {}".format(AELLA_INPUT_CHAIN) in line:
                self._delete_chain_rule_line(line)
        self._run_iptables(
            [
                "-I",
                "INPUT",
                "2",
                "-i",
                iface,
                "-j",
                AELLA_INPUT_CHAIN,
                "-m",
                "comment",
                "--comment",
                AELLA_SYSTEM_JUMP_COMMENT,
            ],
            "Failed to ensure AELLA jump rule",
        )

    def ensure_default_tail_rule_last(self, mode: str) -> None:
        lines = self._read_chain_rule_lines(AELLA_INPUT_CHAIN)
        for line in lines:
            if "AELLA_DEFAULT" in line:
                self._delete_chain_rule_line(line)
        if mode == "whitelist":
            self._run_iptables(
                [
                    "-A",
                    AELLA_INPUT_CHAIN,
                    "-j",
                    "DROP",
                    "-m",
                    "comment",
                    "--comment",
                    AELLA_DEFAULT_WHITELIST_COMMENT,
                ],
                "Failed to ensure default whitelist tail rule",
            )
        else:
            self._run_iptables(
                [
                    "-A",
                    AELLA_INPUT_CHAIN,
                    "-j",
                    "ACCEPT",
                    "-m",
                    "comment",
                    "--comment",
                    AELLA_DEFAULT_BLACKLIST_COMMENT,
                ],
                "Failed to ensure default blacklist tail rule",
            )

    def build_user_rule_args(self, src: str, port: str, mode: str, desc: str) -> list[str]:
        target = "ACCEPT" if mode == "whitelist" else "DROP"
        args = ["-A", AELLA_INPUT_CHAIN]
        any_source = src in ("0.0.0.0/0", "0.0.0.0")
        if not any_source:
            args.extend(["-s", src])
        if port != "all":
            args.extend(["-p", "tcp", "--dport", str(port)])
        comment_value = ACL_COMMENT_PREFIX + (desc or "").strip()
        args.extend(["-m", "comment", "--comment", comment_value, "-j", target])
        return args

    def _rule_signature(self, src: Optional[str], proto: Optional[str], dport: Optional[str], target: Optional[str]) -> tuple:
        src_key = src if src else "0.0.0.0/0"
        dport_key = dport if dport else "all"
        if dport_key != "all":
            proto_key = proto if proto else "tcp"
        else:
            proto_key = proto if proto else "all"
        return (src_key, proto_key, dport_key, target or "")

    def _comment_is_user_acl(self, comment: Optional[str]) -> bool:
        if not comment:
            return False
        if "AELLA_ACL_AUTO" in comment:
            return False
        return comment.startswith(ACL_COMMENT_PREFIX.strip())

    def _comment_is_default_tail(self, comment: Optional[str]) -> bool:
        return bool(comment and comment.startswith("AELLA_DEFAULT"))

    def apply_merge(self, staging_rules: list[dict], state: dict) -> None:
        if not staging_rules:
            print("No staged ACL rules. Nothing to apply.\n")
            return
        self.ensure_aella_chain()
        self.ensure_established_rule()
        self.ensure_jump_rule(state["iface"])

        _, chain_rules = self.parse_chain_rules(AELLA_INPUT_CHAIN)
        existing_keys = set()
        for rule in chain_rules:
            if not self._comment_is_user_acl(rule.get("comment")):
                continue
            existing_keys.add(self._rule_signature(rule.get("src"), rule.get("proto"), rule.get("dport"), rule.get("target")))

        for rule in chain_rules:
            if self._comment_is_default_tail(rule.get("comment")):
                self._delete_chain_rule_line(rule["raw"])

        for rule in staging_rules:
            source = rule.get("source")
            ports = rule.get("ports", [])
            desc = rule.get("desc", "")
            for port in ports:
                args = self.build_user_rule_args(source, port, state["mode"], desc)
                key = self._rule_signature(
                    None if source in ("0.0.0.0/0", "0.0.0.0") else source,
                    "tcp" if port != "all" else None,
                    None if port == "all" else str(port),
                    "ACCEPT" if state["mode"] == "whitelist" else "DROP",
                )
                if key in existing_keys:
                    continue
                self._run_iptables(args, "Failed to apply ACL rule")
                existing_keys.add(key)

        self.ensure_default_tail_rule_last(state["mode"])
        self._clear_acl_staging()

    def apply_reset(self, staging_rules: list[dict], state: dict) -> None:
        if not staging_rules:
            print("No staged ACL rules. Nothing to apply.\n")
            return
        self.ensure_aella_chain()
        self.ensure_established_rule()
        self.ensure_jump_rule(state["iface"])

        lines, parsed = self.parse_chain_rules(AELLA_INPUT_CHAIN)
        for rule in parsed:
            if self._comment_is_user_acl(rule.get("comment")) or self._comment_is_default_tail(rule.get("comment")):
                self._delete_chain_rule_line(rule["raw"])

        for rule in staging_rules:
            source = rule.get("source")
            ports = rule.get("ports", [])
            desc = rule.get("desc", "")
            for port in ports:
                args = self.build_user_rule_args(source, port, state["mode"], desc)
                self._run_iptables(args, "Failed to apply ACL rule")

        self.ensure_default_tail_rule_last(state["mode"])
        self._clear_acl_staging()

    def unset_acl(self, src: str, ports: list[str], state: Optional[dict]) -> tuple[int, int]:
        live_removed = 0
        staged_removed = 0

        if ports != ["all"]:
            normalized_ports = []
            for p in ports:
                p = "icmp" if p == "ping" else p
                if p not in normalized_ports:
                    normalized_ports.append(p)
            ports = normalized_ports

        any_source = src in ("0.0.0.0/0", "0.0.0.0")
        _, chain_rules = self.parse_chain_rules(AELLA_INPUT_CHAIN)
        for rule in chain_rules:
            if not self._comment_is_user_acl(rule.get("comment")):
                continue
            rule_src = rule.get("src")
            if any_source:
                if rule_src and rule_src != "0.0.0.0/0":
                    continue
            else:
                if rule_src != src:
                    continue
            if rule.get("proto") == "icmp":
                rule_port = "icmp"
            else:
                rule_port = rule.get("dport") if rule.get("dport") else "all"
            if "all" in ports:
                if rule_port != "all":
                    continue
            else:
                if rule_port not in [str(p) for p in ports]:
                    continue
            self._delete_chain_rule_line(rule["raw"])
            live_removed += 1

        staging = self._load_acl_staging()
        rules = staging.get("rules", [])
        new_rules = []
        for rule in rules:
            rule_source = rule.get("source")
            rule_ports = [str(p) for p in rule.get("ports", [])]
            if any_source:
                if rule_source not in ("0.0.0.0/0", "0.0.0.0"):
                    new_rules.append(rule)
                    continue
            else:
                if rule_source != src:
                    new_rules.append(rule)
                    continue

            if "all" in ports:
                if "all" in rule_ports:
                    staged_removed += 1
                    continue
                new_rules.append(rule)
                continue

            if "all" in rule_ports:
                new_rules.append(rule)
                continue

            remaining_ports = [p for p in rule_ports if p not in [str(pv) for pv in ports]]
            if remaining_ports != rule_ports:
                staged_removed += 1
            if remaining_ports:
                rule["ports"] = remaining_ports
                new_rules.append(rule)

        if new_rules != rules:
            staging["rules"] = new_rules
            self._save_acl_staging(staging)
        return live_removed, staged_removed

    def show_acl(self) -> str:
        output = "\n"
        output += "=" * 60 + "\n"
        output += "Access Control List (AELLA_ACL rules)\n"
        output += "=" * 60 + "\n"

        state = self._load_acl_state()
        mode = state.get("mode") or "unset"
        iface = state.get("iface") or "unset"
        output += "Mode: {}\n".format(mode)
        output += "Interface: {}\n".format(iface)
        output += "-" * 60 + "\n"

        input_lines = self._read_chain_rule_lines("INPUT")
        established_present = any(AELLA_SYSTEM_ALLOW_ESTABLISHED_COMMENT in line for line in input_lines)
        jump_line = next((line for line in input_lines if AELLA_SYSTEM_JUMP_COMMENT in line), None)
        jump_iface = None
        if jump_line:
            match = re.search(r"-i\s+(\S+)", jump_line)
            if match:
                jump_iface = match.group(1)

        output += "System: established rule: {}\n".format("present" if established_present else "absent")
        if jump_line:
            output += "System: jump rule: present (iface {})\n".format(jump_iface or "unknown")
        else:
            output += "System: jump rule: absent\n"
        output += "-" * 60 + "\n"

        _, rules = self.parse_chain_rules(AELLA_INPUT_CHAIN)
        acl_entries = []
        tail_entry = None
        for rule in rules:
            comment = rule.get("comment") or ""
            if self._comment_is_user_acl(comment):
                target = rule.get("target")
                action = "allow" if target == "ACCEPT" else "deny"
                source = rule.get("src") if rule.get("src") else "0.0.0.0/0"
                port = rule.get("dport") if rule.get("dport") else "all"
                desc = ""
                if comment.startswith(ACL_COMMENT_PREFIX):
                    desc = comment.replace(ACL_COMMENT_PREFIX, "", 1).strip()
                acl_entries.append((action, source, port, desc))
                continue
            if comment.startswith("AELLA_DEFAULT"):
                tail_entry = comment

        if acl_entries:
            for action, source, port, desc in acl_entries:
                if desc:
                    output += "  {} {} {} ({})\n".format(action, source, port, desc)
                else:
                    output += "  {} {} {}\n".format(action, source, port)
        else:
            output += "  No AELLA_ACL rules found\n"

        if tail_entry:
            output += "  [{}]\n".format(tail_entry)

        output += "\n"
        print(output)
        return output

    def compute_apply_risk(self, mode: str, client_ip: Optional[str], staging_rules: list[dict], live_rules: list[dict]) -> tuple[str, str]:
        if not client_ip:
            return ("WARN", "Unable to detect current SSH client IP. Applying may terminate your session and block future access.")

        def _ip_in_sources(ip: str, sources: list[str]) -> bool:
            ip_obj = ipaddress.ip_address(ip)
            for src in sources:
                try:
                    if src in ("0.0.0.0/0", "0.0.0.0"):
                        return True
                    if "/" in src:
                        if ip_obj in ipaddress.ip_network(src, strict=False):
                            return True
                    else:
                        if ip_obj == ipaddress.ip_address(src):
                            return True
                except Exception:
                    continue
            return False

        sources = []
        for rule in staging_rules:
            source = rule.get("source")
            if source:
                sources.append(source)

        if mode == "whitelist":
            if not _ip_in_sources(client_ip, sources):
                return ("HIGH", "Your current SSH client IP is NOT in the allow list. Applying may terminate your session and block future access.")
        if mode == "blacklist":
            if _ip_in_sources(client_ip, sources):
                return ("HIGH", "Your current SSH client IP IS in the deny list. Applying may terminate your session immediately.")

        return ("OK", "No immediate SSH risk detected based on current rules.")

    def confirm_apply_with_risk_summary(self, mode: str, iface: str, client_ip: Optional[str], risk_level: str, risk_message: str) -> bool:
        client_ip_text = client_ip if client_ip else "Unable to detect current SSH client IP"
        summary = (
            "Review before applying ACL.\n\n"
            "Mode: {}\n"
            "Interface: {}\n"
            "SSH Client IP: {}\n"
            "Risk: {}\n\n"
            "{}\n\n"
            "Continue?"
        ).format(mode, iface, client_ip_text, risk_level, risk_message)
        return self._run_whiptail_yesno("ACL Apply Confirmation", summary)

    def _get_mgt_ipv4(self) -> str:
        return self._get_acl_ipv4("mgt")

    def _acl_iface_exists(self, interface: str) -> bool:
        cmd = "ip link show {}".format(interface)
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        _, err = proc.communicate()
        if proc.returncode != 0:
            return False
        if err:
            err_text = err.decode("utf-8", errors="ignore")
            if 'does not exist' in err_text:
                return False
        return True

    def _default_acl_iface(self) -> str:
        if self._acl_iface_exists("mgt"):
            return "mgt"
        if self._acl_iface_exists("host") or self._acl_iface_exists("hostmgmt"):
            return "host"
        return "mgt"

    def _get_acl_ipv4(self, interface: str) -> str:
        interface = interface.strip().lower()
        if interface not in {"mgt", "host"}:
            raise RuntimeError("Unsupported ACL interface: {}".format(interface))
        cmd = "ip -4 addr show dev {}".format(interface)
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        if proc.returncode != 0 or not out:
            if interface == "host":
                cmd_alt = "ip -4 addr show dev hostmgmt"
                proc_alt = subprocess.Popen(cmd_alt, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out_alt, err_alt = proc_alt.communicate()
                if proc_alt.returncode == 0 and out_alt:
                    out = out_alt
                    err = err_alt
                else:
                    err_msg = err.decode("utf-8", errors="ignore").strip() if err else "host IPv4 not found"
                    raise RuntimeError("Failed to get host IPv4 address: {}".format(err_msg))
            else:
                err_msg = err.decode("utf-8", errors="ignore").strip() if err else "mgt IPv4 not found"
                if self._acl_iface_exists("host") or self._acl_iface_exists("hostmgmt"):
                    return self._get_acl_ipv4("host")
                raise RuntimeError("Failed to get mgt IPv4 address: {}".format(err_msg))
        output = out.decode("utf-8", errors="ignore")
        match = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/", output)
        if not match:
            raise RuntimeError("Failed to parse {} IPv4 address".format(interface))
        return match.group(1)

    @staticmethod
    def _is_user_acl_rule_line(rule_line: str) -> bool:
        if "AELLA_ACL_AUTO" in rule_line:
            return False
        return ACL_COMMENT_PREFIX.strip() in rule_line

    def _ensure_local_ip_allow_rules(self):
        """Ensure local interface IPs are always allowed"""
        for dest_ip in ALWAYS_ALLOW_DEST_IPS:
            cidr = "{}/32".format(dest_ip)
            cmd_check = (
                "sudo iptables -C INPUT -d {} -m comment --comment \"{}\" -j ACCEPT"
            ).format(cidr, LOCAL_ALWAYS_ALLOW_COMMENT)
            proc = subprocess.Popen(cmd_check, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc.communicate()

            if proc.returncode != 0:
                cmd_add = (
                    "sudo iptables -I INPUT 1 -d {} -m comment --comment \"{}\" -j ACCEPT"
                ).format(cidr, LOCAL_ALWAYS_ALLOW_COMMENT)
                subprocess.Popen(cmd_add, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()

    def _ensure_established_related_rule(self):
        cmd_check = "sudo iptables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
        proc = subprocess.Popen(cmd_check, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc.communicate()
        if proc.returncode != 0:
            cmd_add = (
                "sudo iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED "
                "-j ACCEPT -m comment --comment \"AELLA_SYSTEM Allow established\""
            )
            subprocess.Popen(cmd_add, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()

    def _purge_legacy_local_always_allow_rules(self):
        """
        Remove legacy destination-based allow rules that bypass deny-all:
          ACCEPT all 0.0.0.0/0 -> <host_ip> /* Local interface IP - always allow */
        Keep only 127.0.0.1, 192.168.0.100, and 192.168.122.1 if such legacy rules exist.
        """
        keep = {"127.0.0.1", "192.168.0.100", "192.168.122.1"}
        cmd = "sudo iptables -L INPUT -n -v --line-numbers"
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, _ = proc.communicate()
        if proc.returncode != 0 or not out:
            return

        lines = out.decode("utf-8", errors="ignore").splitlines()
        to_delete = []
        for line in lines:
            if "Local interface IP - always allow" not in line:
                continue
            parts = line.split()
            if len(parts) < 10:
                continue
            try:
                num = int(parts[0])
            except Exception:
                continue
            dest = parts[9] if len(parts) > 9 else ""
            if dest in keep:
                continue
            to_delete.append(num)

        for num in sorted(to_delete, reverse=True):
            subprocess.Popen(
                "sudo iptables -D INPUT {}".format(num),
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()

    def _get_current_ssh_client_ip(self):
        """Get current SSH client IPv4 address if available"""
        return self.get_current_ssh_client_ip()

    def _iptables_add_auto_ssh(self, ssh_ip):
        """Add auto-allow rule for current SSH client"""
        cidr = "{}/32".format(ssh_ip)
        comment_part = '-m comment --comment "{}"'.format(ACL_AUTO_COMMENT)
        check_cmd = "sudo iptables -C INPUT -s {} -p tcp --dport 22 {} -j ACCEPT".format(cidr, comment_part)
        check_proc = subprocess.Popen(check_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        check_proc.communicate()
        if check_proc.returncode == 0:
            return

        cmd = "sudo iptables -I INPUT -s {} -p tcp --dport 22 {} -j ACCEPT".format(cidr, comment_part)
        subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()

    def _load_acl_staging(self):
        """Load staged ACL rules from file"""
        default_data = {"rules": []}
        try:
            with open(ACL_STAGING_PATH, "r") as f:
                data = json.load(f)
        except FileNotFoundError:
            return default_data
        except PermissionError:
            proc = subprocess.run(
                ["sudo", "cat", ACL_STAGING_PATH],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if proc.returncode != 0 or not proc.stdout:
                return default_data
            try:
                data = json.loads(proc.stdout)
            except json.JSONDecodeError:
                return default_data
        except json.JSONDecodeError:
            return default_data
        except Exception:
            return default_data

        if not isinstance(data, dict) or "rules" not in data or not isinstance(data["rules"], list):
            return default_data
        return data

    def _save_acl_staging(self, data):
        """Save staged ACL rules to file"""
        target_dir = os.path.dirname(ACL_STAGING_PATH)
        make_dir(target_dir, root=True)
        payload = json.dumps(data, indent=2, sort_keys=False)
        tmp_path = "/tmp/acl_staging.json"
        try:
            with open(tmp_path, "w") as f:
                f.write(payload)
            subprocess.run(
                ["sudo", "mv", tmp_path, ACL_STAGING_PATH],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        except Exception:
            try:
                subprocess.run(
                    ["sudo", "tee", ACL_STAGING_PATH],
                    input=payload,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
            except Exception:
                pass

    # =========================
    # ACL HELPERS (NEW DESIGN)
    # =========================

    def _run_cmd(self, cmd: str) -> tuple[int, str, str]:
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        return proc.returncode, (out.decode("utf-8", errors="ignore") if out else ""), (err.decode("utf-8", errors="ignore") if err else "")

    def _load_acl_state(self) -> dict:
        default_data: dict = {}
        try:
            with open(ACL_STATE_PATH, "r") as f:
                data = json.load(f)
        except FileNotFoundError:
            return default_data
        except PermissionError:
            rc, out, _ = self._run_cmd(f"sudo cat {shlex.quote(ACL_STATE_PATH)}")
            if rc != 0 or not out:
                return default_data
            try:
                data = json.loads(out)
            except Exception:
                return default_data
        except Exception:
            return default_data

        if not isinstance(data, dict):
            return default_data
        mode = data.get("mode")
        iface = data.get("iface")
        if mode not in ("whitelist", "blacklist") or not iface:
            return default_data
        return data

    def _save_acl_state(self, data: dict) -> None:
        target_dir = os.path.dirname(ACL_STATE_PATH)
        make_dir(target_dir, root=True)
        payload = json.dumps(data, indent=2, sort_keys=False)
        tmp_path = "/tmp/acl_state.json"
        try:
            with open(tmp_path, "w") as f:
                f.write(payload)
            self._run_cmd(f"sudo mv {shlex.quote(tmp_path)} {shlex.quote(ACL_STATE_PATH)}")
        except Exception:
            self._run_cmd(f"echo {shlex.quote(payload)} | sudo tee {shlex.quote(ACL_STATE_PATH)} >/dev/null")

    def _clear_acl_state(self) -> None:
        self._run_cmd(f"sudo rm -f {shlex.quote(ACL_STATE_PATH)}")

    def _get_iface_ipv4(self, iface: str) -> str:
        # 반드시 ip -4 addr show dev <iface> 로만 취득
        rc, out, err = self._run_cmd(f"ip -4 addr show dev {shlex.quote(iface)}")
        if rc != 0 or not out:
            raise RuntimeError(f"Failed to get IPv4 for iface={iface}: {err.strip()}")
        m = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/", out)
        if not m:
            raise RuntimeError(f"No IPv4 found on iface={iface}")
        return m.group(1)

    def _list_acl_candidate_ifaces(self) -> list[tuple[str, str]]:
        """
        Return list of (iface, ipv4) candidates:
          - has IPv4
          - exclude iface whose IPv4 in ACL_EXCLUDE_IPS (192.168.0.100, 192.168.122.1)
          - exclude lo
        """
        candidates: list[tuple[str, str]] = []
        try:
            for name in os.listdir("/sys/class/net"):
                if name == "lo":
                    continue
                try:
                    ip = self._get_iface_ipv4(name)
                except Exception:
                    continue
                if ip in ACL_EXCLUDE_IPS:
                    continue
                candidates.append((name, ip))
        except Exception:
            pass
        return candidates

    def _iptables_chain_exists(self, chain: str) -> bool:
        rc, _, _ = self._run_cmd(f"sudo iptables -S {shlex.quote(chain)}")
        return rc == 0

    def _iptables_ensure_chain(self, chain: str) -> None:
        if self._iptables_chain_exists(chain):
            return
        self._run_cmd(f"sudo iptables -N {shlex.quote(chain)}")

    def _iptables_flush_chain(self, chain: str) -> None:
        if not self._iptables_chain_exists(chain):
            return
        self._run_cmd(f"sudo iptables -F {shlex.quote(chain)}")

    def _iptables_delete_chain(self, chain: str) -> None:
        if not self._iptables_chain_exists(chain):
            return
        # must be flushed and unreferenced
        self._run_cmd(f"sudo iptables -F {shlex.quote(chain)}")
        self._run_cmd(f"sudo iptables -X {shlex.quote(chain)}")

    def _iptables_rule_check(self, table_chain: str, rule_args: str) -> bool:
        # iptables -C <chain> <args>
        rc, _, _ = self._run_cmd(f"sudo iptables -C {shlex.quote(table_chain)} {rule_args}")
        return rc == 0

    def _iptables_rule_insert(self, table_chain: str, position: int | None, rule_args: str) -> None:
        if position is None:
            cmd = f"sudo iptables -A {shlex.quote(table_chain)} {rule_args}"
        else:
            cmd = f"sudo iptables -I {shlex.quote(table_chain)} {position} {rule_args}"
        self._run_cmd(cmd)

    def _iptables_rule_delete(self, table_chain: str, rule_args: str) -> None:
        self._run_cmd(f"sudo iptables -D {shlex.quote(table_chain)} {rule_args}")

    def _ensure_aella_system_rules(self, iface: str) -> None:
        """
        Ensure ONLY when applying (rules exist):
          - INPUT top: ESTABLISHED,RELATED accept (with comment)
          - INPUT: jump to AELLA_INPUT for selected iface (with comment)
          - AELLA_INPUT chain exists
        """
        self._iptables_ensure_chain(AELLA_INPUT_CHAIN)

        est_args = f'-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT -m comment --comment "{AELLA_SYSTEM_ALLOW_ESTABLISHED_COMMENT}"'
        if not self._iptables_rule_check("INPUT", est_args):
            # place at very top
            self._iptables_rule_insert("INPUT", 1, est_args)

        jump_args = f'-i {shlex.quote(iface)} -j {AELLA_INPUT_CHAIN} -m comment --comment "{AELLA_SYSTEM_JUMP_COMMENT}"'
        if not self._iptables_rule_check("INPUT", jump_args):
            # place just after established if possible
            self._iptables_rule_insert("INPUT", 2, jump_args)

    def _remove_aella_system_rules(self) -> None:
        """
        Remove AELLA-managed rules from INPUT and delete chain.
        Used ONLY by: set acl policy (re-init).
        """
        # delete jump rules (may exist multiple times)
        rc, out, _ = self._run_cmd("sudo iptables -S INPUT")
        if rc == 0 and out:
            for line in out.splitlines():
                if not line.startswith("-A INPUT"):
                    continue
                if AELLA_SYSTEM_JUMP_COMMENT in line or AELLA_SYSTEM_ALLOW_ESTABLISHED_COMMENT in line:
                    del_line = line.replace("-A INPUT", "-D INPUT", 1)
                    self._run_cmd("sudo iptables " + del_line)

        # flush/delete chain
        self._iptables_delete_chain(AELLA_INPUT_CHAIN)

    def _build_user_rule_args(self, iface: str, iface_ip: str, action: str, source: str, port: str, desc: str) -> str:
        """
        Build rule args for AELLA_INPUT_CHAIN.
        MUST include -d <iface_ip>/32 always.
        MUST include comment with ACL_COMMENT_PREFIX.
        """
        target = "ACCEPT" if action == "allow" else "DROP"
        iface_part = f"-i {shlex.quote(iface)}"
        dest_part = f"-d {iface_ip}/32"
        any_source = source in ("0.0.0.0/0", "0.0.0.0")
        comment_value = (ACL_COMMENT_PREFIX + (desc or "").strip()).strip()
        escaped_comment = comment_value.replace('"', '\\"')
        comment_part = f'-m comment --comment "{escaped_comment}"'

        src_part = "" if any_source else f"-s {source}"
        if port == "all":
            proto_part = ""
        elif port in ("icmp", "ping"):
            proto_part = "-p icmp --icmp-type echo-request"
        else:
            proto_part = f"-p tcp --dport {port}"

        args = " ".join(x for x in [iface_part, src_part, dest_part, proto_part, "-j " + target, comment_part] if x).strip()
        return args

    def _normalize_acl_source(self, source: str | None) -> str | None:
        if not source:
            return None
        if source in ("0.0.0.0/0", "0.0.0.0"):
            return None
        if "/" not in source:
            return f"{source}/32"
        return source

    def _port_to_proto_dport(self, port: str) -> tuple[str | None, str | None]:
        if port == "all":
            return (None, None)
        if port in ("icmp", "ping"):
            return ("icmp", None)
        return ("tcp", str(port))

    def _user_rule_exists_in_chain(self, chain_rules: list[dict], action: str, source: str, port: str) -> bool:
        target = "ACCEPT" if action == "allow" else "DROP"
        src_norm = self._normalize_acl_source(source)
        proto, dport = self._port_to_proto_dport(port)
        for rule in chain_rules:
            if rule.get("target") != target:
                continue
            rule_src = rule.get("src")
            if src_norm is None:
                if rule_src not in (None, "0.0.0.0/0", "0.0.0.0"):
                    continue
            else:
                if rule_src != src_norm:
                    continue
            if proto is None:
                if rule.get("proto") is not None:
                    continue
            else:
                if rule.get("proto") != proto:
                    continue
            if dport is None:
                if rule.get("dport") is not None:
                    continue
            else:
                if rule.get("dport") != dport:
                    continue
            return True
        return False

    def _append_user_rule_summary(self, chain_rules: list[dict], action: str, source: str, port: str) -> None:
        target = "ACCEPT" if action == "allow" else "DROP"
        src_norm = self._normalize_acl_source(source)
        proto, dport = self._port_to_proto_dport(port)
        chain_rules.append(
            {
                "raw": "",
                "src": src_norm,
                "proto": proto,
                "dport": dport,
                "target": target,
                "comment": None,
            }
        )

    def _ensure_default_tail_rule_last(self, mode: str, iface_ip: str) -> None:
        # remove existing default tail first (both types), then append correct one
        rc, out, _ = self._run_cmd(f"sudo iptables -S {AELLA_INPUT_CHAIN}")
        if rc == 0 and out:
            for line in out.splitlines():
                if not line.startswith(f"-A {AELLA_INPUT_CHAIN}"):
                    continue
                if AELLA_DEFAULT_WHITELIST_COMMENT in line or AELLA_DEFAULT_BLACKLIST_COMMENT in line:
                    del_line = line.replace(f"-A {AELLA_INPUT_CHAIN}", f"-D {AELLA_INPUT_CHAIN}", 1)
                    self._run_cmd("sudo iptables " + del_line)

        if mode == "whitelist":
            tail_args = f'-d {iface_ip}/32 -j DROP -m comment --comment "{AELLA_DEFAULT_WHITELIST_COMMENT}"'
        else:
            tail_args = f'-d {iface_ip}/32 -j ACCEPT -m comment --comment "{AELLA_DEFAULT_BLACKLIST_COMMENT}"'

        # append only if not exists
        if not self._iptables_rule_check(AELLA_INPUT_CHAIN, tail_args):
            self._iptables_rule_insert(AELLA_INPUT_CHAIN, None, tail_args)

    def _detect_ssh_client_ip(self) -> str | None:
        return self._get_current_ssh_client_ip()

    def _client_ip_in_cidr(self, client_ip: str, cidr: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(client_ip)
            net_obj = ipaddress.ip_network(cidr, strict=False)
            return ip_obj in net_obj
        except Exception:
            return False

    def _compute_whitelist_ssh_risk(self, client_ip: str | None, staged_rules: list[dict]) -> tuple[str, str]:
        """
        Returns (risk_level, message).
        HIGH if cannot prove client_ip has allow rule for tcp/22 or all.
        """
        if not client_ip:
            return ("HIGH", "Unable to detect current SSH client IP. Applying ACL may terminate your session and block future access.")

        # Need a rule that allows client_ip and includes port 22 or all.
        for r in staged_rules:
            if r.get("action") != "allow":
                continue
            src = r.get("source", "0.0.0.0/0")
            ports = r.get("ports", [])
            if not ports:
                continue
            if not ("all" in ports or "22" in ports):
                continue
            # Match source
            if src in ("0.0.0.0/0", "0.0.0.0"):
                # allow any -> safe for ssh
                return ("LOW", f"Current SSH client IP {client_ip} will be allowed (0.0.0.0/0 includes SSH).")
            if "/" in src:
                if self._client_ip_in_cidr(client_ip, src):
                    return ("LOW", f"Current SSH client IP {client_ip} is included in allow CIDR {src} for SSH.")
            else:
                if client_ip == src:
                    return ("LOW", f"Current SSH client IP {client_ip} is explicitly allowed for SSH.")
        return ("HIGH", f"Your current SSH client IP {client_ip} is NOT allowed for SSH(22). Applying may terminate your session and lock you out.")

    def _confirm_yes(self, prompt: str) -> bool:
        val = input(prompt).strip()
        return val == "YES"

    def _clear_acl_staging(self):
        """Clear staged ACL rules"""
        self._save_acl_staging({"rules": []})

    def _persist_iptables_rules(self) -> bool:
        """Persist current iptables rules so they survive reboot.

        Preferred: netfilter-persistent save
        Fallback : iptables-save > /etc/iptables/rules.v4
        """
        try:
            # 0) Persist ipset (required before iptables-restore on boot)
            if shutil.which("ipset"):
                p = subprocess.run(
                    ["sudo", "sh", "-c", "ipset save > /etc/ipset.conf"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                if p.returncode != 0:
                    warn = (p.stderr or p.stdout or "").strip()
                    print(f"[WARN] ipset save failed: {warn}")
                if shutil.which("systemctl"):
                    svc = subprocess.run(
                        ["sudo", "systemctl", "enable", "--now", "ipset-persistent"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        check=False,
                    )
                    if svc.returncode != 0:
                        warn = (svc.stderr or svc.stdout or "").strip()
                        print(f"[WARN] ipset-persistent service enable failed: {warn}")

            # 1) Preferred path (Ubuntu standard)
            if shutil.which("netfilter-persistent"):
                p = subprocess.run(
                    ["sudo", "netfilter-persistent", "save"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                if p.returncode == 0:
                    return True
                warn = (p.stderr or p.stdout or "").strip()
                print(f"[WARN] netfilter-persistent save failed: {warn}")

            # 2) Fallback path
            if shutil.which("iptables-save"):
                p = subprocess.run(
                    ["sudo", "sh", "-c", "iptables-save > /etc/iptables/rules.v4"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                if p.returncode == 0:
                    return True
                warn = (p.stderr or p.stdout or "").strip()
                print(f"[WARN] iptables-save fallback failed: {warn}")

            print("[WARN] Unable to persist iptables rules (netfilter-persistent/iptables-save not found).")
            return False
        except Exception as e:
            print(f"[WARN] Persist iptables rules failed: {e}")
            return False

    def _stage_rule(self, action, source, ports, desc):
        """Stage a rule in ACL staging file, avoid duplicates"""
        data = self._load_acl_staging()
        rules = data.get("rules", [])
        staged_rule = {
            "action": action,
            "source": source,
            "ports": ports,
            "desc": desc or "",
        }
        for rule in rules:
            if rule.get("action") == staged_rule["action"] and rule.get("source") == staged_rule["source"] and rule.get("ports") == staged_rule["ports"]:
                return False
        rules.append(staged_rule)
        data["rules"] = rules
        self._save_acl_staging(data)
        return True

    def _iptables_add(self, action, source, ports, desc, dest_ip=None):
        """Add ACL rules to iptables with comment prefix"""
        if not dest_ip:
            dest_ip = self._get_mgt_ipv4()
        dest_part = "-d {}/32".format(dest_ip)
        comment_value = ACL_COMMENT_PREFIX + (desc or "").strip()
        escaped_comment = comment_value.replace('"', '\\"').replace('$', '\\$').replace('`', '\\`')
        comment_part = '-m comment --comment "{}"'.format(escaped_comment)
        any_source = source in ("0.0.0.0/0", "0.0.0.0")

        for port in ports:
            if self._iptables_rule_exists(action, source, port, dest_ip=dest_ip):
                continue
            if port == 'all':
                if action == 'allow':
                    if any_source:
                        cmd = "sudo iptables -I INPUT {} {} -j ACCEPT".format(dest_part, comment_part).strip()
                    else:
                        cmd = "sudo iptables -I INPUT -s {} {} {} -j ACCEPT".format(source, dest_part, comment_part).strip()
                else:
                    if any_source:
                        cmd = "sudo iptables -I INPUT {} {} -j DROP".format(dest_part, comment_part).strip()
                    else:
                        cmd = "sudo iptables -I INPUT -s {} {} {} -j DROP".format(source, dest_part, comment_part).strip()
            else:
                if action == 'allow':
                    if any_source:
                        cmd = "sudo iptables -I INPUT -p tcp --dport {} {} {} -j ACCEPT".format(port, dest_part, comment_part).strip()
                    else:
                        cmd = "sudo iptables -I INPUT -s {} -p tcp --dport {} {} {} -j ACCEPT".format(source, port, dest_part, comment_part).strip()
                else:
                    if any_source:
                        cmd = "sudo iptables -I INPUT -p tcp --dport {} {} {} -j DROP".format(port, dest_part, comment_part).strip()
                    else:
                        cmd = "sudo iptables -I INPUT -s {} -p tcp --dport {} {} {} -j DROP".format(source, port, dest_part, comment_part).strip()

            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = proc.communicate()
            if proc.returncode != 0:
                error_msg = err.decode('utf-8', errors='ignore') if err else 'Unknown error'
                if 'comment' in error_msg.lower() or 'match' in error_msg.lower():
                    cmd_no_comment = cmd.replace(comment_part, '').replace('  ', ' ').strip()
                    subprocess.Popen(cmd_no_comment, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()

    def _iptables_rule_exists(self, action, source, port, dest_ip=None):
        """Check if a semantically equivalent rule already exists via iptables -C"""
        target = "ACCEPT" if action == "allow" else "DROP"
        any_source = source in ("0.0.0.0/0", "0.0.0.0")
        if not dest_ip:
            dest_ip = self._get_mgt_ipv4()
        dest_part = "-d {}/32".format(dest_ip)

        base_parts = ["sudo iptables -C INPUT", dest_part]
        if port != "all":
            base_parts.append("-p tcp --dport {}".format(port))
        base_parts.append("-j {}".format(target))
        base_cmd = " ".join(base_parts)

        if not any_source:
            check_cmd = "{} -s {}".format(base_cmd, source)
            proc = subprocess.Popen(check_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc.communicate()
            return proc.returncode == 0

        check_cmds = [
            "{} -s 0.0.0.0/0".format(base_cmd),
            base_cmd,
        ]
        for check_cmd in check_cmds:
            proc = subprocess.Popen(check_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc.communicate()
            if proc.returncode == 0:
                return True
        return False

    def _iptables_delete_user_rules(self):
        """Delete user ACL rules with AELLA_ACL prefix from INPUT chain"""
        cmd = "sudo iptables -S INPUT"
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, _ = proc.communicate()
        if proc.returncode != 0 or not out:
            return

        lines = out.decode('utf-8', errors='ignore').split('\n')
        for line in lines:
            if not line.startswith("-A INPUT"):
                continue
            if not self._is_user_acl_rule_line(line):
                continue
            del_cmd = "sudo iptables " + line.replace("-A INPUT", "-D INPUT", 1)
            subprocess.Popen(del_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()

    def set_acl_callback(self, key, param):
        """
        NEW ACL UX:

          set acl policy
          set acl <IP/network> <port|icmp|ping> [...] | all [description]
          set acl apply [--reset]

        IMPORTANT:
          - policy only sets mode/iface, DOES NOT touch iptables.
          - apply does NOTHING if staged rules are empty (no iptables changes at all).
        """
        # -----------------------
        # Helper: print usage
        # -----------------------
        def _print_usage(policy_missing: bool):
            print("")
            if policy_missing:
                print("ACL policy is not initialized.")
                print("You must run 'set acl policy' before adding or applying any ACL rules.")
                print("")
            print("------------------------------------------------------------")
            print("Required first step:")
            print("  set acl policy        Initialize ACL mode (whitelist/blacklist) and target interface")
            print("")
            print("------------------------------------------------------------")
            print("ACL rule syntax (available after policy is initialized):")
            print("  set acl <IP/network> <port|icmp|ping|all> [description]")
            print("")
            print("  IP/network : IP address (e.g., 192.168.1.100) or network (e.g., 192.168.1.0/24)")
            print("  port       : Port number (e.g., 22, 80, 443), \"icmp\"/\"ping\", or \"all\" for all ports")
            print("               Multiple ports can be specified separated by space")
            print("  description: Optional description/comment")
            print("")
            print("------------------------------------------------------------")
            print("Apply staged rules (rules must exist):")
            print("  set acl apply          Apply staged ACL rules (merge)")
            print("  set acl apply --reset  Reset applied ACL rules and rebuild from staging")
            print("")
            print("------------------------------------------------------------")
            print("Examples:")
            print("  set acl policy")
            print("  set acl 192.168.1.100 22 \"Admin SSH access\"")
            print("  set acl 192.168.1.0/24 80 443 \"Web servers\"")
            print("  set acl 10.0.0.0/8 all \"Internal network\"")
            print("  set acl apply")
            print("")

        # no args => show usage (policy-first)
        if not param:
            state = self._load_acl_state()
            _print_usage(policy_missing=(not state))
            return

        # -----------------------
        # set acl policy
        # -----------------------
        if param[0].lower() == "policy":
            warning = (
                "\nWARNING: Re-initializing ACL policy will DELETE ALL existing AELLA ACL rules (live) and staged rules.\n"
                "This action cannot be undone.\n\n"
                "Type YES to continue: "
            )
            if not self._confirm_yes(warning):
                print("\nCanceled.\n")
                return

            # destructive cleanup
            self._clear_acl_staging()
            self._clear_acl_state()
            self._remove_aella_system_rules()

            # select mode
            print("\nSelect ACL mode:")
            print("  1) whitelist  (specified sources are ALLOWED, all others are DENIED)")
            print("  2) blacklist  (specified sources are DENIED, all others are ALLOWED)")
            mode_sel = input("Enter 1 or 2: ").strip()
            if mode_sel not in ("1", "2"):
                print("\nInvalid selection. Canceled.\n")
                return
            mode = "whitelist" if mode_sel == "1" else "blacklist"

            # select iface (single)
            candidates = self._list_acl_candidate_ifaces()
            if not candidates:
                print("\nNo eligible interfaces found (IPv4 required; excluding 192.168.0.100, 192.168.122.1).\n")
                return

            print("\nSelect target interface (exactly ONE):")
            for idx, (ifn, ip) in enumerate(candidates, start=1):
                print(f"  {idx}) {ifn}  (IPv4: {ip})")
            sel = input("Enter number: ").strip()
            if not sel.isdigit() or not (1 <= int(sel) <= len(candidates)):
                print("\nInvalid selection. Canceled.\n")
                return
            iface, iface_ip = candidates[int(sel) - 1]

            self._save_acl_state({"mode": mode, "iface": iface, "iface_ip": iface_ip})
            print("\nPolicy saved.")
            print("  mode : {}".format(mode))
            print("  iface: {} (IPv4: {})".format(iface, iface_ip))
            print("\nNOTE: No firewall rules are active until at least one ACL rule is added and 'set acl apply' is executed.\n")
            return

        # -----------------------
        # set acl apply [--reset]
        # -----------------------
        if param[0].lower() == "apply":
            # policy must exist
            state = self._load_acl_state()
            if not state:
                print("\nACL policy is not initialized. Run 'set acl policy' first.\n")
                return

            # parse options
            reset = False
            tokens = param[1:]
            for t in tokens:
                if t == "--reset":
                    reset = True
                else:
                    print("\nInvalid option. Use: set acl apply [--reset]\n")
                    return

            data = self._load_acl_staging()
            rules = data.get("rules", [])
            if not rules:
                print("\nNo ACL rules defined. Nothing to apply.")
                print("Policy-only does not enforce allow/deny all. (No iptables changes were made.)\n")
                return

            # SSH risk warning (mandatory)
            mode = state["mode"]
            client_ip = self._detect_ssh_client_ip()
            if mode == "whitelist":
                risk_level, risk_msg = self._compute_whitelist_ssh_risk(client_ip, rules)
                print("\n[SSH Safety Check]")
                print(risk_msg)
                if risk_level == "HIGH":
                    if not self._confirm_yes("\nType YES to apply anyway (HIGH RISK): "):
                        print("\nCanceled. No changes applied.\n")
                        return
                else:
                    if not self._confirm_yes("\nType YES to apply: "):
                        print("\nCanceled. No changes applied.\n")
                        return
            else:
                # blacklist: still warn generally
                print("\n[SSH Safety Check]")
                if client_ip:
                    print(f"Current SSH client IP detected: {client_ip}")
                print("Applying ACL may terminate your current session depending on rules.")
                if not self._confirm_yes("\nType YES to apply: "):
                    print("\nCanceled. No changes applied.\n")
                    return

            # APPLY (rules exist -> now allowed to touch iptables)
            iface = state["iface"]
            iface_ip = self._get_iface_ipv4(iface)

            # ensure base system rules and chain/jump
            self._ensure_aella_system_rules(iface)

            if reset:
                self._iptables_flush_chain(AELLA_INPUT_CHAIN)

            # add user rules (append order)
            _, existing_rules = self.parse_chain_rules(AELLA_INPUT_CHAIN)
            for r in rules:
                action = r.get("action")
                source = r.get("source")
                ports = r.get("ports", [])
                desc = r.get("desc", "")
                if not action or not source or not ports:
                    continue
                for p in ports:
                    if self._user_rule_exists_in_chain(existing_rules, action, source, p):
                        continue
                    args = self._build_user_rule_args(iface, iface_ip, action, source, p, desc)
                    if not self._iptables_rule_check(AELLA_INPUT_CHAIN, args):
                        self._iptables_rule_insert(AELLA_INPUT_CHAIN, None, args)
                        self._append_user_rule_summary(existing_rules, action, source, p)

            # ensure default tail last
            self._ensure_default_tail_rule_last(state["mode"], iface_ip)

            # clear staging after successful apply
            self._clear_acl_staging()
            self._persist_iptables_rules()
            if reset:
                print("\nApplied staged ACL rules with reset (rebuild completed).")
            else:
                print("\nApplied staged ACL rules (merge completed).")
            print("Staging cleared.\n")
            return

        # -----------------------
        # set acl <src> <ports...|all> [desc]
        # -----------------------
        state = self._load_acl_state()
        if not state:
            print("\nACL policy is not initialized. Run 'set acl policy' first.\n")
            return

        # param[0] must be source
        source = param[0]
        # Validate IP/network
        if "/" in source:
            parts = source.split("/")
            if not self.valid_ipv4_address(parts[0]) or not parts[1].isdigit() or int(parts[1]) > 32:
                print("\nInvalid network format: Use CIDR notation (e.g., 192.168.1.0/24)\n")
                return
        else:
            if not self.valid_ipv4_address(source):
                print("\nInvalid IP address format: {}\n".format(source))
                return

        if len(param) < 2:
            print("\nPort specification required.\n")
            return

        remaining = param[1:]
        ports: list[str] = []
        description: str | None = None

        for i, p in enumerate(remaining):
            if p == "all" or p in ("icmp", "ping") or p.isdigit():
                ports.append(p)
            else:
                description = " ".join(remaining[i:])
                break

        if not ports:
            print("\nPort specification required.\n")
            return

        if "all" in ports:
            if len(ports) > 1:
                print('\nCannot specify "all" with other ports\n')
                return
            ports = ["all"]

        if ports != ["all"]:
            normalized_ports = []
            for p in ports:
                p = "icmp" if p == "ping" else p
                if p not in normalized_ports:
                    normalized_ports.append(p)
            ports = normalized_ports

        # validate ports
        if ports != ["all"]:
            for p in ports:
                if p in ("icmp", "ping"):
                    continue
                try:
                    n = int(p)
                    if n < 1 or n > 65535:
                        print("\nInvalid port number: {} (must be 1-65535)\n".format(p))
                        return
                except Exception:
                    print("\nInvalid port number: {}\n".format(p))
                    return

        if description:
            description = description.strip('"').strip("'").strip()

        # derive action by mode
        mode = state["mode"]
        action = "allow" if mode == "whitelist" else "deny"

        staged = self._stage_rule(action, source, ports, description)
        if staged:
            if mode == "whitelist":
                print('Staged (ALLOW/whitelist): {} {} ({})\n'.format(source, " ".join(ports), description or ""))
            else:
                print('Staged (DENY/blacklist): {} {} ({})\n'.format(source, " ".join(ports), description or ""))
        else:
            print("ACL rule already staged.\n")

    def unset_ntp_callback(self, key, param):
        if not param or param[0].endswith('?') or len(param) < 1:
            print('\n<NTP server> \t Specify NTP server name or IP address\n')
            return
        if "--force" in param:
            print("--force is not supported; only CLI-managed NTP peers may be removed")
            return 1
        target = self._normalize_ntp_target(" ".join(param))
        if not self._is_valid_ntp_target(target):
            print("Invalid NTP hostname: Please enter the correct hostname")
            return 1
        if self._ntpsec_operation("unset", [target]):
            print("Successfully unset ntp {}\n".format(" ".join(param)))
            return 0
        return 1


    def unset_acl_callback(self, key, param):
        """
        NEW:
          unset acl <IP/network> <port|icmp|ping> [...] | all

        Removes from BOTH:
          - staging
          - live AELLA_INPUT_CHAIN (only AELLA-managed user rules)
        """
        if not param or len(param) < 2:
            print("\n<IP/network> <port|icmp|ping> [...] | all  Remove ACL rule")
            print("Examples:")
            print("  unset acl 192.168.1.100 22")
            print("  unset acl 192.168.1.0/24 80 443")
            print("  unset acl 10.0.0.0/8 all\n")
            return

        state = self._load_acl_state()
        if not state:
            print("\nACL policy is not initialized. Run 'set acl policy' first.\n")
            return

        source = param[0]
        if "/" in source:
            parts = source.split("/")
            if not self.valid_ipv4_address(parts[0]) or not parts[1].isdigit() or int(parts[1]) > 32:
                print("\nInvalid network format: Use CIDR notation (e.g., 192.168.1.0/24)\n")
                return
        else:
            if not self.valid_ipv4_address(source):
                print("\nInvalid IP address format: {}\n".format(source))
                return

        ports = param[1:]
        if "all" in ports:
            if len(ports) > 1:
                print('\nCannot specify "all" with other ports\n')
                return
            ports = ["all"]
        else:
            # validate port numbers
            for p in ports:
                if p in ("icmp", "ping"):
                    continue
                if not p.isdigit():
                    print("\nInvalid port: {}\n".format(p))
                    return
                n = int(p)
                if n < 1 or n > 65535:
                    print("\nInvalid port number: {} (must be 1-65535)\n".format(p))
                    return

            normalized_ports = []
            for p in ports:
                p = "icmp" if p == "ping" else p
                if p not in normalized_ports:
                    normalized_ports.append(p)
            ports = normalized_ports

        # 1) remove from staging
        data = self._load_acl_staging()
        rules = data.get("rules", [])
        before = len(rules)
        # match by source+ports regardless of action/desc
        new_rules = [r for r in rules if not (r.get("source") == source and r.get("ports") == ports)]
        data["rules"] = new_rules
        self._save_acl_staging(data)
        staged_removed = before - len(new_rules)

        # 2) remove from live chain (only AELLA user rules)
        live_removed = 0
        iface = state["iface"]
        iface_ip = None
        try:
            iface_ip = self._get_iface_ipv4(iface)
        except Exception:
            iface_ip = None

        if iface_ip and self._iptables_chain_exists(AELLA_INPUT_CHAIN):
            # delete rules by reconstructing rule args; try both -s omitted and -s 0.0.0.0/0 when any
            mode = state["mode"]
            action = "allow" if mode == "whitelist" else "deny"

            for p in ports:
                desc_candidates = [""]  # we don't know desc; we will delete by scanning and matching -s/-d/--dport/-j and prefix.
                # Safer approach: scan -S chain and delete matching lines
                rc, out, _ = self._run_cmd(f"sudo iptables -S {AELLA_INPUT_CHAIN}")
                if rc == 0 and out:
                    for line in out.splitlines():
                        if not line.startswith(f"-A {AELLA_INPUT_CHAIN}"):
                            continue
                        if ACL_COMMENT_PREFIX.strip() not in line:
                            continue
                        if "-d {}/32".format(iface_ip) not in line:
                            continue
                        # port match
                        if p == "all":
                            if "--dport" in line:
                                continue
                        else:
                            if p in ("icmp", "ping"):
                                if "-p icmp" not in line:
                                    continue
                                if "--icmp-type" in line and "--icmp-type 8" not in line and "--icmp-type echo-request" not in line:
                                    continue
                            elif f"--dport {p}" not in line:
                                continue
                        # target match
                        want_target = "ACCEPT" if action == "allow" else "DROP"
                        if f"-j {want_target}" not in line:
                            continue
                        # source match (any-source equivalence)
                        if source in ("0.0.0.0/0", "0.0.0.0"):
                            # accept both: with -s 0.0.0.0/0 OR no -s
                            pass
                        else:
                            if f"-s {source}" not in line:
                                continue

                        del_line = line.replace(f"-A {AELLA_INPUT_CHAIN}", f"-D {AELLA_INPUT_CHAIN}", 1)
                        self._run_cmd("sudo iptables " + del_line)
                        live_removed += 1

        if staged_removed or live_removed:
            if live_removed > 0:
                self._persist_iptables_rules()
            print(f"\nRemoved {live_removed} live rule(s), removed {staged_removed} staged rule(s).\n")
        else:
            print("\nNo matching ACL rules found to remove.\n")
            print('Use "show acl" to see current rules.\n')

    def unset_interface_callback(self, key, param):
        if param and param[0].rstrip("?") == "mgt":
            if len(param) < 2 or param[0].endswith("?"):
                print("\nip         Unset management IP address and netmask")
                print("gateway    Unset management default gateway")
                print("restart    Restart management interface\n")
                return
            option = param[1]
            if option == "ip":
                changed = self._apply_mgt_transaction(remove_address=True, remove_netmask=True)
            elif option == "gateway":
                changed = self._apply_mgt_transaction(remove_gateway=True)
            elif option == "restart":
                self._apply_mgt_transaction(restart=True)
                return
            else:
                print('Invalid option: Available options are "ip", "gateway" and "restart"')
                return
            if changed and self._mgt_last_changed:
                print("Run 'unset interface mgt restart' command to apply the changes.\n")
            return
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
                print("\nPress [Enter]\n")
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
                    print('Could not find the default gateway on the interface {}\n'.format(interface))
                    return 
                m = re.match('default\s+via\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+dev\s+(\w+)', res[0].decode('utf-8'))
                if not m.group(1) == interface:
                    print('Could not delete the default gateway due to interface mismatch\n')
                    return
                cmd_del = 'ip route del {} table 2'.format(m.group(0).rstrip())
                p = subprocess.Popen(cmd_del, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                res = p.communicate()
                if res[1]:
                    print('Could not delete the default gateway on the interface {} or the default gateway was already deleted\n'.format(interface))
                    print(res[1].decode('utf-8').rstrip())
                print('Successfully deleted the default gateway: {}\n'.format(m.group(0)))

            except Exception as e:
                print('Could not delete the default gateway\n')

        elif option == 'restart':
             print('Restarting network interface. You need to use new IP address to reconnect...\n')
             self._restart_interface_with_verification(interface)

    def complete_unset(self, text, line, begidx, endidx):
        if not text:
            completions = self.unset_command_help.keys()
        elif line.startswith('unset interface'):
            return self.complete_unset_interface(text, line, begidx, endidx)
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
        if not hostname:
            return False
        if hostname[-1] == ".":
            hostname = hostname[:-1]
        if not hostname:
            return False
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
                print("Successfully applied updates")
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
                cmd = "virsh dominfo {} 2>/dev/null".format(vm_name)
                proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, err = proc.communicate()
                if out:
                    parsed = self._parse_virsh_autostart(out.decode('utf-8', errors='ignore'))
                    if parsed is True:
                        enable = False
                    elif parsed is False:
                        enable = True
                    else:
                        enable = True
                else:
                    enable = True
            except Exception:
                # If check fails, default to enable
                enable = True

        # Execute virsh autostart command
        try:
            if enable:
                cmd = "virsh autostart {}".format(vm_name)
            else:
                cmd = "virsh autostart --disable {}".format(vm_name)
            result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode != 0:
                err_msg = result.stderr.strip() if result.stderr else "Unknown error"
                print("Failed to configure auto start for VM '{}': {}\n".format(vm_name, err_msg))
                return

            check_cmd = "virsh dominfo {} 2>/dev/null".format(vm_name)
            check_proc = subprocess.Popen(check_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, _ = check_proc.communicate()
            status = 'unknown'
            if out:
                parsed = self._parse_virsh_autostart(out.decode('utf-8', errors='ignore'))
                if parsed is True:
                    status = 'enabled'
                elif parsed is False:
                    status = 'disabled'
            print("VM '{}' auto start status: {}\n".format(vm_name, status))
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
                print('Invalid option: Available option is "history"')
                print('\nhistory    Clear CLI history\n')
                return
            elif (len(param) == 1 and re.match('history[?]', param[0])) or \
                (len(param) == 2 and re.match('history', param[0]) and re.match('^[?]$', param[1])):
                print('\nPress [Enter]\n')
                return
        try:
            current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            cli_log_file  = '/var/log/aella/aella_cli.log'
            cli_log_backup = cli_log_file + '_' + current_time.replace(' ', '_').replace(':','')

            cmd = 'cp -a {0} {1}'.format(cli_log_file, cli_log_backup)
            p = subprocess.call(cmd, shell=True)
            if not p == 0:
                print('Failed to copy: {}'.format(cmd))
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
            print('                List all running VMs with detailed resource usage\n')
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
        
        # Handle 'monitor vm' - list VMs with detailed CPU/memory usage
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
            
            # Get system CPU cores for reference
            cmd = "nproc"
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, _ = proc.communicate()
            total_cores = int(out.decode('utf-8', errors='ignore').strip()) if out else 1
            
            # Get total memory for reference
            try:
                with open('/proc/meminfo', 'r') as f:
                    meminfo = f.read()
                    mem_total_kb = 0
                    for line in meminfo.split('\n'):
                        if line.startswith('MemTotal:'):
                            mem_total_kb = int(line.split()[1])
                            break
                mem_total_gb = mem_total_kb / (1024.0 * 1024.0)
            except Exception:
                mem_total_gb = 0
            
            # Print header
            print('\n' + '=' * 140)
            print('VM Resource Usage Monitor')
            print('=' * 140)
            print('{:<15} {:<8} {:<12} {:<12} {:<12} {:<10} {:<12} {:<12} {:<12} {:<8} {:<8}'.format(
                'VM', 'PID', 'CPU(top%)', 'CPU(host%)', 'CPU(vcpu%)', 'RSS(GB)', 'Mem(host%)', 'Mem(alloc%)', 'Alloc(GB)', 'vCPU', 'Status'))
            print('-' * 140)
            
            # For each VM, get detailed resource usage
            for vm in vm_list:
                pid_file = '/run/libvirt/qemu/{}.pid'.format(vm)
                if not os.path.exists(pid_file):
                    continue
                
                try:
                    with open(pid_file, 'r') as f:
                        pid = f.read().strip()
                    
                    # Get CPU, RSS, and threads using top (more accurate for multi-threaded processes)
                    # Use top -b -n 1 for batch mode, single iteration
                    cmd = "top -b -n 1 -p {} 2>/dev/null | tail -1".format(pid)
                    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    out, err = proc.communicate()
                    
                    cpu_percent = 0.0
                    rss_kb = 0
                    threads = 0
                    
                    if proc.returncode == 0 and out:
                        # Parse top output: PID USER PR NI VIRT RES SHR S %CPU %MEM TIME+ COMMAND
                        line = out.decode('utf-8', errors='ignore').strip()
                        parts = line.split()
                        if len(parts) >= 10:
                            try:
                                cpu_percent = float(parts[8])  # %CPU column
                                # Get RSS from ps (top's RES is in KiB but we need exact value)
                                cmd_ps = "ps -p {} -o rss,nlwp --no-headers".format(pid)
                                proc_ps = subprocess.Popen(cmd_ps, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                                out_ps, _ = proc_ps.communicate()
                                if proc_ps.returncode == 0 and out_ps:
                                    ps_parts = out_ps.decode('utf-8', errors='ignore').strip().split()
                                    if len(ps_parts) >= 2:
                                        rss_kb = int(ps_parts[0].strip())
                                        threads = int(ps_parts[1].strip())
                            except (ValueError, IndexError):
                                # Fallback to ps if top parsing fails
                                cmd_ps = "ps -p {} -o %cpu,rss,nlwp --no-headers".format(pid)
                                proc_ps = subprocess.Popen(cmd_ps, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                                out_ps, _ = proc_ps.communicate()
                                if proc_ps.returncode == 0 and out_ps:
                                    ps_parts = out_ps.decode('utf-8', errors='ignore').strip().split()
                                    if len(ps_parts) >= 3:
                                        cpu_percent = float(ps_parts[0].strip())
                                        rss_kb = int(ps_parts[1].strip())
                                        threads = int(ps_parts[2].strip())
                    
                    # If we still don't have data, try ps as fallback
                    if rss_kb == 0:
                        cmd_ps = "ps -p {} -o rss,nlwp --no-headers".format(pid)
                        proc_ps = subprocess.Popen(cmd_ps, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        out_ps, _ = proc_ps.communicate()
                        if proc_ps.returncode == 0 and out_ps:
                            ps_parts = out_ps.decode('utf-8', errors='ignore').strip().split()
                            if len(ps_parts) >= 2:
                                rss_kb = int(ps_parts[0].strip())
                                threads = int(ps_parts[1].strip())
                    
                    if rss_kb > 0:
                        rss_mb = rss_kb / 1024.0
                        rss_gb = rss_kb / 1024.0 / 1024.0
                        
                        # Get VM memory allocation from virsh (use "Memory" field which is current allocation, not "Max memory")
                        try:
                            # Try "Memory" first (current allocated memory)
                            cmd = "virsh dominfo {} 2>/dev/null | grep -i '^Memory:' | awk '{{print $2}}'".format(vm)
                            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            out, _ = proc.communicate()
                            if out:
                                allocated_mem_kb = int(out.decode('utf-8', errors='ignore').strip())
                                allocated_mem_mb = allocated_mem_kb / 1024.0
                            else:
                                # Fallback to "Max memory" if "Memory" not available
                                cmd = "virsh dominfo {} 2>/dev/null | grep -i 'Max memory' | awk '{{print $3}}'".format(vm)
                                proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                                out, _ = proc.communicate()
                                if out:
                                    allocated_mem_kb = int(out.decode('utf-8', errors='ignore').strip())
                                    allocated_mem_mb = allocated_mem_kb / 1024.0
                                else:
                                    allocated_mem_mb = 0
                        except Exception:
                            allocated_mem_mb = 0
                        
                        # Get CPU allocation (vCPUs)
                        try:
                            cmd = "virsh dominfo {} 2>/dev/null | grep -i 'CPU(s)' | awk '{{print $2}}'".format(vm)
                            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            out, _ = proc.communicate()
                            if out:
                                vcpus = int(out.decode('utf-8', errors='ignore').strip())
                            else:
                                vcpus = threads  # fallback to thread count
                        except Exception:
                            vcpus = threads
                        
                        # Calculate normalized values
                        cpu_host_percent = cpu_percent / total_cores if total_cores > 0 else 0
                        cpu_vcpu_percent = cpu_percent / vcpus if vcpus > 0 else 0
                        mem_host_percent = (rss_kb / mem_total_kb) * 100 if mem_total_kb > 0 else 0
                        alloc_gb = allocated_mem_mb / 1024.0 if allocated_mem_mb > 0 else 0
                        mem_alloc_percent = (rss_mb / allocated_mem_mb) * 100 if allocated_mem_mb > 0 else 0
                        
                        # Determine status based on host thresholds
                        status = 'OK'
                        # CPU(host%): > 80 CRIT, > 50 WARN
                        if cpu_host_percent > 80:
                            status = 'CRIT'
                        elif cpu_host_percent > 50:
                            status = 'WARN'
                        
                        # Mem(host%): > 90 CRIT, > 75 WARN
                        if mem_host_percent > 90:
                            status = 'CRIT' if status != 'CRIT' else 'CRIT'
                        elif mem_host_percent > 75:
                            status = 'WARN' if status == 'OK' else status
                        
                        # Format output
                        cpu_top_str = '{:.1f}'.format(cpu_percent)
                        cpu_host_str = '{:.1f}'.format(cpu_host_percent)
                        cpu_vcpu_str = '{:.1f}'.format(cpu_vcpu_percent)
                        rss_gb_str = '{:.2f}'.format(rss_gb)
                        mem_host_str = '{:.1f}'.format(mem_host_percent)
                        mem_alloc_str = '{:.1f}'.format(mem_alloc_percent) if allocated_mem_mb > 0 else 'N/A'
                        alloc_gb_str = '{:.2f}'.format(alloc_gb) if allocated_mem_mb > 0 else 'N/A'
                        
                        print('{:<15} {:<8} {:<12} {:<12} {:<12} {:<10} {:<12} {:<12} {:<12} {:<8} {:<8}'.format(
                            vm, pid, cpu_top_str, cpu_host_str, cpu_vcpu_str, rss_gb_str, 
                            mem_host_str, mem_alloc_str, alloc_gb_str, vcpus, status))
                    else:
                        # Skip VM if we can't get RSS
                        continue
                except Exception as e:
                    # Skip VM if we can't get its info
                    continue
            
            print('-' * 140)
            print('Legend:')
            print('  CPU(host%): >50 WARN, >80 CRIT (CPU(top%) / {} cores)'.format(total_cores))
            print('  Mem(host%): >75 WARN, >90 CRIT (RSS / host MemTotal)')
            print('  CPU(vcpu%) / Mem(alloc%): Reference metrics only (not used for Status determination)')
            print('  Use "monitor vm htop <VM Name>" for detailed process monitoring')
            print('')
        except Exception as e:
            print('Failed to monitor VMs: {}\n'.format(e))

    def monitor_system_callback(self, key, param):
        """Check system health status"""
        try:
            # 1. CPU load
            try:
                with open('/proc/loadavg', 'r') as f:
                    loadavg = f.read().strip().split()
                    load_1min = float(loadavg[0])
                    load_5min = float(loadavg[1])
                    load_15min = float(loadavg[2])
                
                # Get CPU core count
                cmd = "nproc"
                proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, _ = proc.communicate()
                cpu_cores = int(out.decode('utf-8', errors='ignore').strip()) if out else 1
                
                # Calculate per-core load
                per_core_1min = load_1min / cpu_cores if cpu_cores > 0 else 0
                per_core_5min = load_5min / cpu_cores if cpu_cores > 0 else 0
                per_core_15min = load_15min / cpu_cores if cpu_cores > 0 else 0
                
                # Determine status based on per-core load
                if per_core_1min > 1.0:
                    status = 'CRIT'
                elif per_core_1min > 0.7:
                    status = 'WARN'
                else:
                    status = 'OK'
                
                print('[{}]   load: {:.1f} {:.1f} {:.1f} (cores={}, per-core={:.2f} {:.2f} {:.2f})'.format(
                    status, load_1min, load_5min, load_15min, cpu_cores, 
                    per_core_1min, per_core_5min, per_core_15min))
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
                    mem_total_gb = mem_total / (1024.0 * 1024.0)
                    mem_available_gb = mem_available / (1024.0 * 1024.0)
                    
                    if mem_percent > 20:
                        print('[OK]   mem: {:.0f}% available ({:.0f}GiB / {:.0f}GiB)'.format(
                            mem_percent, mem_available_gb, mem_total_gb))
                    else:
                        print('[WARN] mem: {:.0f}% available ({:.0f}GiB / {:.0f}GiB)'.format(
                            mem_percent, mem_available_gb, mem_total_gb))
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
                        used = parts[2]  # Used column
                        size = parts[1]  # Size column
                        if usage < 80:
                            print('[OK]   /: {}% used ({} / {})'.format(usage, used, size))
                        else:
                            print('[WARN] /: {}% used ({} / {})'.format(usage, used, size))
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
                            used = parts[2]  # Used column
                            size = parts[1]  # Size column
                            if usage < 80:
                                print('[OK]   /stellar: {}% used ({} / {})'.format(usage, used, size))
                            else:
                                print('[WARN] /stellar: {}% used ({} / {})'.format(usage, used, size))
            except Exception as e:
                pass  # Silently skip if /stellar doesn't exist or can't be checked
            
            # 6. libvirt service status
            try:
                libvirt_status = None
                # Try libvirtd first (older systems)
                cmd = "systemctl is-active libvirtd 2>/dev/null"
                proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, _ = proc.communicate()
                if proc.returncode == 0 and out:
                    libvirt_status = out.decode('utf-8', errors='ignore').strip()
                else:
                    # Try virtqemud (newer systems)
                    cmd = "systemctl is-active virtqemud 2>/dev/null"
                    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    out, _ = proc.communicate()
                    if proc.returncode == 0 and out:
                        libvirt_status = out.decode('utf-8', errors='ignore').strip()
                
                if libvirt_status:
                    # Get VM counts
                    running_count = 0
                    defined_count = 0
                    try:
                        # Get running VMs
                        cmd = "virsh list --name 2>/dev/null"
                        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        out, _ = proc.communicate()
                        if proc.returncode == 0 and out:
                            running_list = [vm.strip() for vm in out.decode('utf-8', errors='ignore').split('\n') if vm.strip()]
                            running_count = len(running_list)
                        
                        # Get all defined VMs
                        cmd = "virsh list --all --name 2>/dev/null"
                        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        out, _ = proc.communicate()
                        if proc.returncode == 0 and out:
                            defined_list = [vm.strip() for vm in out.decode('utf-8', errors='ignore').split('\n') if vm.strip()]
                            defined_count = len(defined_list)
                    except Exception:
                        pass  # If VM count fails, just show service status
                    
                    if libvirt_status == 'active':
                        if running_count > 0 or defined_count > 0:
                            print('[OK]   libvirt: active (vms running {} / defined {})'.format(running_count, defined_count))
                        else:
                            print('[OK]   libvirt: active')
                    else:
                        print('[WARN] libvirt: {}'.format(libvirt_status))
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
                    print("There is no history associated with the specified patch")
                    return
                state = patch_history[patch].get("state", "Unknown")
                log_file = "{}/{}.log".format(PATCH_LOG_DIR,
                                              patch)
                if not os.path.isfile(log_file):
                    print("There is no history associated with the specified patch")
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

    @staticmethod
    def _should_debug():
        return os.environ.get("AELLA_CLI_DEBUG") == "1"

    def _debug_print(self, msg):
        if self._should_debug():
            print(msg)

    def write_full_interfaces_file(self, lines):
        main_path = NETWORK_INTERFACES_PATH
        try:
            _atomic_replace_text_file(
                main_path,
                "\n".join([line.rstrip("\n") for line in lines]) + "\n",
            )
            with open(main_path, 'r') as f:
                final = f.read()
            if not final.strip():
                print("Failed to update interface configuration: file is empty")
                return False
            if "iface lo inet loopback" not in final and "source /etc/network/interfaces.d/*" not in final:
                print("Failed to update interface configuration: missing base stanza/source")
                return False
            return True
        except Exception as e:
            print('Failed to update interface configuration')
            print(e)
            return False

    def update_interface_file(self, interface, contents):
        """Update interface configuration file block only.
        For DP appliances: mgt in /etc/network/interfaces, data1g/data10g in interfaces.d/
        For Sensor/KVM installers: mgt/host/hostmgmt in /etc/network/interfaces.d/*.cfg
        """
        if interface == "mgt":
            print("Management interface must use the canonical management editor")
            return False
        try:
            for line in contents:
                if re.match(r'^\s*source\s+/etc/network/interfaces\.d/\*', line):
                    print("Invalid interface block contents: contains source line")
                    return False
                if re.match(r'^\s*iface\s+lo\s+inet\s+loopback', line):
                    print("Invalid interface block contents: contains loopback stanza")
                    return False

            new_block = [line.rstrip("\n") for line in contents]
            cfg_path = self._find_iface_config_path(interface)
            main_path = "/etc/network/interfaces"

            if cfg_path and cfg_path != main_path:
                return self._write_iface_config_file_with_backup(cfg_path, new_block)

            if os.path.exists(main_path):
                with open(main_path, 'r') as f:
                    existing = f.read().splitlines()
            else:
                existing = []

            start = None
            end = None
            in_block = False
            for idx, line in enumerate(existing):
                if re.match(r'^\s*(auto|iface)\s+{}\b'.format(re.escape(interface)), line):
                    if start is None:
                        start = idx
                        in_block = True
                elif in_block and re.match(r'^\s*(auto|iface)\s+\S+', line):
                    end = idx
                    in_block = False
                    break
            if start is not None and end is None:
                end = len(existing)

            if start is None:
                if self._uses_interfaces_d_source() and interface in self._SENSOR_IFACE_CFG_HINTS:
                    target = self._default_iface_config_path(interface)
                    if target != main_path:
                        return self._write_iface_config_file_with_backup(target, new_block)
                updated = existing + ([""] if existing and existing[-1].strip() else []) + new_block
            else:
                updated = existing[:start] + new_block + existing[end:]

            return self._write_interfaces_file_with_backup(updated)
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

    def _parse_set_interface_args(self, tokens):
        parsed = {"ip": None, "gateway": None, "dns": [], "restart": False}
        i = 0
        while i < len(tokens):
            key = tokens[i].lower()
            if key == "restart":
                parsed["restart"] = True
                i += 1
                continue
            if key not in {"ip", "gateway", "dns"}:
                raise ValueError("Invalid option: {}".format(tokens[i]))
            if i + 1 >= len(tokens):
                raise ValueError("Missing value for {}".format(tokens[i]))
            if key == "ip":
                parsed["ip"] = tokens[i + 1]
                i += 2
            elif key == "gateway":
                parsed["gateway"] = tokens[i + 1]
                i += 2
            else:
                dns_list = []
                i += 1
                while i < len(tokens) and tokens[i].lower() not in {"ip", "gateway", "dns", "restart"}:
                    dns_list.append(tokens[i])
                    i += 1
                if not dns_list:
                    raise ValueError("Missing DNS server IP address")
                parsed["dns"] = dns_list
        return parsed

    @staticmethod
    def _read_text_exact(path):
        with open(path, "r", encoding="utf-8", newline="") as stream:
            return stream.read()

    @staticmethod
    def _mgt_static_stanza_bounds(text):
        lines = text.splitlines(keepends=True)
        starts = [
            index for index, line in enumerate(lines)
            if re.match(r"^\s*iface\s+mgt\s+inet\s+static(?:\s*(?:#.*)?)?(?:\r?\n)?$", line)
        ]
        if len(starts) != 1:
            raise ValueError(
                "Canonical management configuration must contain exactly one "
                "'iface mgt inet static' stanza"
            )
        start = starts[0]
        end = len(lines)
        for index in range(start + 1, len(lines)):
            if re.match(r"^\s*iface\s+\S+\s+", lines[index]):
                end = index
                break
        return lines, start, end

    def _render_mgt_ipv4_config(
        self,
        original,
        address=None,
        netmask=None,
        gateway=None,
        dns_nameservers=None,
        remove_address=False,
        remove_netmask=False,
        remove_gateway=False,
        remove_dns=False,
    ):
        lines, start, end = self._mgt_static_stanza_bounds(original)
        replacements = {
            "address": (address, remove_address),
            "netmask": (netmask, remove_netmask),
            "gateway": (gateway, remove_gateway),
            "dns-nameservers": (dns_nameservers, remove_dns),
        }
        if address is not None:
            try:
                ipaddress.IPv4Address(address)
            except Exception as exc:
                raise ValueError("Invalid management IPv4 address") from exc
        if netmask is not None:
            try:
                network = ipaddress.IPv4Network("0.0.0.0/{}".format(netmask))
                netmask = str(network.netmask)
                replacements["netmask"] = (netmask, remove_netmask)
            except Exception as exc:
                raise ValueError("Invalid management IPv4 netmask") from exc
        if gateway is not None:
            try:
                ipaddress.IPv4Address(gateway)
            except Exception as exc:
                raise ValueError("Invalid management gateway") from exc
        if dns_nameservers is not None:
            if isinstance(dns_nameservers, str):
                dns_nameservers = dns_nameservers.split()
            normalized_dns = []
            for dns in dns_nameservers:
                try:
                    normalized_dns.append(str(ipaddress.IPv4Address(dns)))
                except Exception as exc:
                    raise ValueError("Invalid management DNS server: {}".format(dns)) from exc
            replacements["dns-nameservers"] = (normalized_dns, remove_dns)

        directive_indexes = {name: [] for name in replacements}
        indent = None
        newline = "\r\n" if "\r\n" in original else "\n"
        for index in range(start + 1, end):
            match = re.match(r"^(\s*)(address|netmask|gateway|dns-nameservers)\s+", lines[index])
            if match:
                directive_indexes[match.group(2)].append(index)
                if indent is None:
                    indent = match.group(1)
        indent = indent if indent is not None else "    "

        output = list(lines)
        insertions = []
        for name, (value, remove) in replacements.items():
            indexes = directive_indexes[name]
            if remove:
                for index in indexes:
                    output[index] = ""
                continue
            if value is None:
                for index in indexes[1:]:
                    output[index] = ""
                continue
            rendered_value = " ".join(value) if name == "dns-nameservers" else str(value)
            if indexes:
                original_line = lines[indexes[0]]
                original_body = original_line.rstrip("\r\n")
                original_newline = original_line[len(original_body):]
                original_indent = re.match(r"^(\s*)", original_body).group(1)
                inline_comment = re.search(r"(\s+#.*)$", original_body)
                comment_suffix = inline_comment.group(1) if inline_comment else ""
                output[indexes[0]] = "{}{} {}{}{}".format(
                    original_indent,
                    name,
                    rendered_value,
                    comment_suffix,
                    original_newline,
                )
                for index in indexes[1:]:
                    output[index] = ""
            else:
                insertions.append(
                    "{}{} {}{}".format(indent, name, rendered_value, newline)
                )
        if insertions:
            output[end:end] = insertions
        return "".join(output)

    def _update_mgt_ipv4_config(
        self,
        ip_cidr=None,
        gateway=None,
        dns_servers=None,
        remove_ip=False,
        remove_gateway=False,
        remove_dns=False,
    ):
        changes = {
            "gateway": gateway,
            "dns_nameservers": dns_servers,
            "remove_address": remove_ip,
            "remove_netmask": remove_ip,
            "remove_gateway": remove_gateway,
            "remove_dns": remove_dns,
        }
        if ip_cidr is not None:
            try:
                value = ipaddress.IPv4Interface(ip_cidr)
            except Exception as exc:
                raise ValueError("Invalid management IP address: {}".format(ip_cidr)) from exc
            changes["address"] = str(value.ip)
            changes["netmask"] = str(value.network.netmask)
        return self._apply_mgt_transaction(**changes)

    @staticmethod
    def _remove_mgt_from_noncanonical_text(text):
        lines = text.splitlines(keepends=True)
        output = []
        changed = False
        index = 0
        while index < len(lines):
            line = lines[index]
            activation = re.match(
                r"^(\s*)(auto|allow-hotplug)(\s+)([^#\r\n]*?)(\s*(?:#.*)?)(\r?\n)?$",
                line,
            )
            if activation:
                tokens = activation.group(4).split()
                if "mgt" in tokens:
                    changed = True
                    tokens = [token for token in tokens if token != "mgt"]
                    if tokens:
                        output.append(
                            "{}{}{}{}{}{}".format(
                                activation.group(1), activation.group(2), activation.group(3),
                                " ".join(tokens), activation.group(5), activation.group(6) or "",
                            )
                        )
                    index += 1
                    continue
            if re.match(r"^\s*iface\s+mgt\s+inet\s+static(?:\s|$)", line):
                changed = True
                index += 1
                while index < len(lines) and not re.match(
                    r"^\s*(iface|auto|allow-hotplug|source|source-directory|mapping)\b",
                    lines[index],
                ):
                    index += 1
                continue
            output.append(line)
            index += 1
        return "".join(output), changed

    def _collect_mgt_transaction(self, **changes):
        if not os.path.isfile(MGT_CONFIG_PATH):
            raise ValueError("Management configuration not found: {}".format(MGT_CONFIG_PATH))
        originals = {MGT_CONFIG_PATH: self._read_text_exact(MGT_CONFIG_PATH)}
        updated = {
            MGT_CONFIG_PATH: self._render_mgt_ipv4_config(originals[MGT_CONFIG_PATH], **changes)
        }
        candidates = []
        if os.path.isfile(NETWORK_INTERFACES_PATH):
            candidates.append(NETWORK_INTERFACES_PATH)
        if os.path.isdir(NETWORK_INTERFACES_DIR):
            for name in sorted(os.listdir(NETWORK_INTERFACES_DIR)):
                path = os.path.join(NETWORK_INTERFACES_DIR, name)
                if name.endswith(".cfg") and path != MGT_CONFIG_PATH and os.path.isfile(path):
                    candidates.append(path)
        final_texts = {MGT_CONFIG_PATH: updated[MGT_CONFIG_PATH]}
        for path in candidates:
            original = self._read_text_exact(path)
            cleaned, changed = self._remove_mgt_from_noncanonical_text(original)
            final_texts[path] = cleaned
            if changed:
                originals[path] = original
                updated[path] = cleaned
        static_locations = []
        for path, text in final_texts.items():
            count = len(re.findall(
                r"(?m)^\s*iface\s+mgt\s+inet\s+static(?:\s*(?:#.*)?)?$",
                text,
            ))
            static_locations.extend([path] * count)
        if static_locations != [MGT_CONFIG_PATH]:
            raise ValueError(
                "Management configuration must contain exactly one canonical "
                "'iface mgt inet static' stanza"
            )
        return originals, updated

    @staticmethod
    def _restore_text_files(originals, paths):
        failed_paths = []
        for path in reversed(paths):
            try:
                _atomic_replace_text_file(path, originals[path])
            except Exception:
                failed_paths.append(path)
        return list(reversed(failed_paths))

    def _apply_mgt_transaction(self, restart=False, **changes):
        self._mgt_last_changed = False
        try:
            originals, updated = self._collect_mgt_transaction(**changes)
        except Exception as exc:
            if str(exc).startswith("Management configuration not found:"):
                print(str(exc))
            else:
                print("Failed to update management configuration: {}".format(exc))
            return False
        write_order = [path for path in updated if path != MGT_CONFIG_PATH]
        write_order.append(MGT_CONFIG_PATH)
        changed_paths = [path for path in write_order if updated[path] != originals[path]]
        self._mgt_last_changed = bool(changed_paths)
        prepared = {}
        written = []
        try:
            for path in changed_paths:
                prepared[path] = _prepare_atomic_text_file(path, updated[path])
        except Exception as exc:
            for temporary_path in prepared.values():
                try:
                    os.unlink(temporary_path)
                except FileNotFoundError:
                    pass
            self._mgt_last_changed = False
            print("Failed to prepare management configuration: {}".format(exc))
            return False
        try:
            for path in changed_paths:
                try:
                    _commit_prepared_text_file(path, prepared[path])
                except _AtomicCommitError as exc:
                    if exc.replaced:
                        written.append(path)
                    raise
                written.append(path)
        except Exception as exc:
            failed_restore_paths = self._restore_text_files(originals, written)
            self._mgt_last_changed = False
            print("Failed to update management configuration: {}".format(exc))
            if failed_restore_paths:
                print(
                    "CRITICAL: Failed to restore management configuration: {}".format(
                        ", ".join(map(os.fspath, failed_restore_paths))
                    )
                )
            return False
        finally:
            for temporary_path in prepared.values():
                try:
                    os.unlink(temporary_path)
                except FileNotFoundError:
                    pass
        if restart and not self._restart_mgt_interface():
            failed_restore_paths = self._restore_text_files(originals, written)
            self._mgt_last_changed = False
            if failed_restore_paths:
                print(
                    "CRITICAL: Failed to restore management configuration: {}".format(
                        ", ".join(map(os.fspath, failed_restore_paths))
                    )
                )
            elif not self._restart_mgt_interface():
                print(
                    "CRITICAL: The previous management configuration was restored "
                    "on disk but could not be re-applied to the live interface. "
                    "Manual network recovery is required."
                )
            return False
        return True

    def _restart_mgt_interface(self):
        try:
            canonical = self._read_text_exact(MGT_CONFIG_PATH)
            lines, start, end = self._mgt_static_stanza_bounds(canonical)
            address = None
            netmask = None
            gateway = None
            for line in lines[start + 1:end]:
                match = re.match(r"^\s*(address|netmask|gateway)\s+(\S+)", line)
                if not match:
                    continue
                if match.group(1) == "address":
                    address = match.group(2)
                elif match.group(1) == "netmask":
                    netmask = match.group(2)
                else:
                    gateway = match.group(2)
            expected_ip = None
            if address and netmask:
                prefix = ipaddress.IPv4Network("0.0.0.0/{}".format(netmask)).prefixlen
                expected_ip = str(ipaddress.IPv4Interface("{}/{}".format(address, prefix)))
            elif address:
                raise ValueError("Management address requires a netmask")
        except Exception as exc:
            print("Failed to read management configuration: {}".format(exc))
            return False

        def read_runtime_addresses():
            proc = subprocess.run(
                ["ip", "-4", "-o", "addr", "show", "dev", "mgt", "scope", "global"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
            )
            if proc.returncode != 0:
                error = (proc.stderr or "").strip()
                message = "Failed to read management IPv4 addresses"
                if error:
                    message += ": {}".format(error)
                print(message)
                return None

            addresses = []
            for match in re.finditer(r"\binet\s+(\S+)", proc.stdout or ""):
                try:
                    normalized = str(ipaddress.IPv4Interface(match.group(1)))
                except Exception:
                    print(
                        "Failed to parse management IPv4 address: {}".format(
                            match.group(1)
                        )
                    )
                    return None
                addresses.append(normalized)
            return addresses

        def read_runtime_routes():
            proc = subprocess.run(
                ["ip", "-4", "route", "show", "table", "main", "default"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
            )
            if proc.returncode != 0:
                error = (proc.stderr or "").strip()
                message = "Failed to read main routing table"
                if error:
                    message += ": {}".format(error)
                print(message)
                return None
            return proc.stdout or ""

        def verify_expected_route(runtime_routes):
            expected_gateway_missing = gateway and not re.search(
                r"(?m)^\s*default\s+via\s+{}\s+dev\s+mgt(?:\s|$)".format(
                    re.escape(gateway)
                ),
                runtime_routes,
            )
            unexpected_gateway = not gateway and re.search(
                r"(?m)^\s*default(?:\s+via\s+\S+)?\s+dev\s+mgt(?:\s|$)",
                runtime_routes,
            )
            return not expected_gateway_missing and not unexpected_gateway

        commands = [
            ["ifup", "--no-act", "mgt"],
            ["sudo", "ifdown", "--force", "mgt"],
            ["sudo", "ifup", "mgt"],
        ]
        for command in commands:
            proc = subprocess.run(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, check=False,
            )
            if proc.returncode != 0:
                error = (proc.stderr or "").strip()
                message = "Failed to restart management interface: {}".format(
                    " ".join(command)
                )
                if error:
                    message += ": {}".format(error)
                print(message)
                return False

        # The configuration file has already been replaced at this point.  An
        # ifdown based on the new file can therefore leave the old runtime IP on
        # the interface.  Before deleting anything, first make sure the new IP
        # and its route are live so an invalid new configuration does not remove
        # the only working management address.
        runtime_addresses = read_runtime_addresses()
        if runtime_addresses is None:
            return False
        if expected_ip and expected_ip not in runtime_addresses:
            print(
                "Failed to verify new management IPv4 address: expected {}, found {}".format(
                    expected_ip,
                    ", ".join(runtime_addresses) if runtime_addresses else "none",
                )
            )
            return False

        runtime_routes = read_runtime_routes()
        if runtime_routes is None or not verify_expected_route(runtime_routes):
            print("Failed to verify main routing table")
            return False

        # Converge the live interface to the canonical configuration.  Keep the
        # expected address and remove every stale global IPv4 address left by
        # the previous configuration.  For an explicit unset, remove them all.
        stale_addresses = [
            item for item in runtime_addresses if expected_ip is None or item != expected_ip
        ]
        for stale_address in stale_addresses:
            proc = subprocess.run(
                ["sudo", "ip", "-4", "addr", "del", stale_address, "dev", "mgt"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
            )
            if proc.returncode != 0:
                # The address may have disappeared asynchronously.  Re-read it
                # before treating the deletion as a failure.
                current_addresses = read_runtime_addresses()
                if current_addresses is None or stale_address in current_addresses:
                    error = (proc.stderr or "").strip()
                    message = "Failed to remove stale management IPv4 address {}".format(
                        stale_address
                    )
                    if error:
                        message += ": {}".format(error)
                    print(message)
                    return False

        final_addresses = read_runtime_addresses()
        if final_addresses is None:
            return False
        expected_addresses = [expected_ip] if expected_ip else []
        if sorted(final_addresses) != sorted(expected_addresses):
            print(
                "Failed to converge management IPv4 addresses: expected {}, found {}".format(
                    ", ".join(expected_addresses) if expected_addresses else "none",
                    ", ".join(final_addresses) if final_addresses else "none",
                )
            )
            return False

        # Re-check the route after stale addresses have been removed.  The CLI
        # reports success only when both the persistent file and live state are
        # consistent with the requested management configuration.
        runtime_routes = read_runtime_routes()
        if runtime_routes is None or not verify_expected_route(runtime_routes):
            print("Failed to verify main routing table")
            return False
        return True

    def _set_mgt_interface(self, param):
        if len(param) < 2:
            print("Management interface option is required")
            return False
        if param[1] == "restart":
            if self._apply_mgt_transaction(restart=True):
                print("Management interface restarted successfully.")
                return True
            return False
        try:
            parsed = self._parse_set_interface_args(param[1:])
        except ValueError as exc:
            print(str(exc))
            return False
        changes = {
            "gateway": parsed["gateway"],
            "dns_nameservers": parsed["dns"] or None,
        }
        if parsed["ip"] is not None:
            try:
                value = ipaddress.IPv4Interface(parsed["ip"])
            except Exception:
                print("Invalid IP address format: {}".format(parsed["ip"]))
                return False
            changes["address"] = str(value.ip)
            changes["netmask"] = str(value.network.netmask)
        result = self._apply_mgt_transaction(restart=parsed["restart"], **changes)
        if not result:
            return False
        if parsed["restart"]:
            print("Management interface restarted successfully.")
            return True
        if self._mgt_last_changed:
            print("Configuration updated successfully.")
            print("Run 'set interface mgt restart' to apply the changes.")
        return True

    _SENSOR_IFACE_CFG_HINTS = {
        "mgt": ["01-mgt.cfg"],
        "host": ["01-host.cfg"],
        "hostmgmt": ["02-hostmgmt.cfg"],
        "data1g": ["01-data1g.cfg"],
        "data10g": ["10-data10g.cfg"],
    }

    def _uses_interfaces_d_source(self):
        main_path = "/etc/network/interfaces"
        if not os.path.exists(main_path):
            return os.path.isdir("/etc/network/interfaces.d")
        try:
            with open(main_path, 'r') as f:
                for line in f:
                    if re.match(r'^\s*source\s+/etc/network/interfaces\.d/\*', line):
                        return True
        except Exception:
            pass
        return False

    def _iface_defined_in_file(self, interface, path):
        if not path or not os.path.exists(path):
            return False
        try:
            with open(path, 'r') as f:
                for line in f:
                    if re.match(r'^\s*(auto|iface|allow-hotplug)\s+{}\b'.format(re.escape(interface)), line):
                        return True
        except Exception:
            return False
        return False

    def _find_iface_config_path(self, interface):
        """Return the config file that defines *interface*, or None."""
        interfaces_d = "/etc/network/interfaces.d"
        main_path = "/etc/network/interfaces"

        for name in self._SENSOR_IFACE_CFG_HINTS.get(interface, []):
            candidate = os.path.join(interfaces_d, name)
            if self._iface_defined_in_file(interface, candidate):
                return candidate

        if os.path.isdir(interfaces_d):
            for name in sorted(os.listdir(interfaces_d)):
                if not name.endswith('.cfg'):
                    continue
                candidate = os.path.join(interfaces_d, name)
                if self._iface_defined_in_file(interface, candidate):
                    return candidate

        if self._iface_defined_in_file(interface, main_path):
            return main_path
        return None

    def _default_iface_config_path(self, interface):
        """Return preferred write path when an interface block does not exist yet."""
        interfaces_d = "/etc/network/interfaces.d"
        hints = self._SENSOR_IFACE_CFG_HINTS
        if interface in hints and (os.path.isdir(interfaces_d) or self._uses_interfaces_d_source()):
            return os.path.join(interfaces_d, hints[interface][0])
        return "/etc/network/interfaces"

    def _write_iface_config_file_with_backup(self, path, contents):
        try:
            normalized = [line.rstrip("\n") for line in contents]
            _atomic_replace_text_file(path, "\n".join(normalized) + "\n")
            return True
        except Exception as e:
            print('Failed to update interface configuration')
            print(e)
            return False

    def _read_interface_config_lines(self, interface):
        cfg_path = self._find_iface_config_path(interface)
        if cfg_path:
            try:
                with open(cfg_path, 'r') as f:
                    return f.readlines()
            except Exception:
                return []
        return []

    def _interface_block_exists(self, interface):
        return self._find_iface_config_path(interface) is not None

    def _resolve_iface_config_name(self, interface):
        if not self.is_sensor_host_mode():
            return interface
        if interface == "host":
            if self._interface_block_exists(interface):
                return interface
            if self._interface_block_exists("hostmgmt"):
                return "hostmgmt"
        return interface

    def _netmask_to_cidr(self, netmask):
        try:
            packed = socket.inet_aton(netmask)
            bits = bin(struct.unpack("!I", packed)[0]).count("1")
            return bits
        except Exception:
            return None

    def _get_interface_expected_config(self, interface):
        config_interface = self._resolve_iface_config_name(interface)
        lines = self._read_interface_config_lines(config_interface)
        in_block = False
        address = None
        netmask = None
        dns_list = []
        for line in lines:
            if re.match(r'^\s*(auto|iface)\s+{}\b'.format(re.escape(config_interface)), line):
                in_block = True
            elif in_block and re.match(r'^\s*(auto|iface)\s+\S+', line):
                in_block = False
            if not in_block:
                continue
            addr_match = re.match(r'^\s*address\s+(\S+)', line)
            if addr_match:
                address = addr_match.group(1)
            netmask_match = re.match(r'^\s*netmask\s+(\S+)', line)
            if netmask_match:
                netmask = netmask_match.group(1)
            dns_match = re.match(r'^\s*dns-nameservers\s+(.+)', line)
            if dns_match:
                dns_list = [d for d in dns_match.group(1).strip().split() if self.valid_ipv4_address(d)]
        expected_ip = None
        if address:
            if netmask:
                cidr = self._netmask_to_cidr(netmask)
                if cidr is not None:
                    expected_ip = "{}/{}".format(address, cidr)
            if expected_ip is None:
                expected_ip = address
        return expected_ip, dns_list

    def _get_interface_netmask(self, interface):
        config_interface = self._resolve_iface_config_name(interface)
        lines = self._read_interface_config_lines(config_interface)
        in_block = False
        netmask = None
        for line in lines:
            if re.match(r'^\s*(auto|iface)\s+{}\b'.format(re.escape(config_interface)), line):
                in_block = True
            elif in_block and re.match(r'^\s*(auto|iface)\s+\S+', line):
                in_block = False
            if not in_block:
                continue
            netmask_match = re.match(r'^\s*netmask\s+(\S+)', line)
            if netmask_match:
                netmask = netmask_match.group(1)
        return netmask

    def _get_interface_gateway(self, interface):
        config_interface = self._resolve_iface_config_name(interface)
        lines = self._read_interface_config_lines(config_interface)
        in_block = False
        gateway = None
        for line in lines:
            if re.match(r'^\s*(auto|iface)\s+{}\b'.format(re.escape(config_interface)), line):
                in_block = True
            elif in_block and re.match(r'^\s*(auto|iface)\s+\S+', line):
                in_block = False
            if not in_block:
                continue
            gw_match = re.match(r'^\s*gateway\s+(\S+)', line)
            if gw_match:
                gateway = gw_match.group(1)
        return gateway

    def _ensure_interfaces_base(self):
        main_path = "/etc/network/interfaces"
        contents = []
        if os.path.exists(main_path):
            with open(main_path, 'r') as f:
                contents = f.read().splitlines()
        has_lo = any(re.match(r'^\s*iface\s+lo\s+inet\s+loopback', line) for line in contents)
        has_auto_lo = any(re.match(r'^\s*auto\s+lo\b', line) for line in contents)
        has_source = any(re.match(r'^\s*source\s+/etc/network/interfaces\.d/\*', line) for line in contents)
        changed = False

        if not has_auto_lo:
            contents.insert(0, "auto lo")
            changed = True
        if not has_lo:
            insert_at = 1 if contents and contents[0].strip() == "auto lo" else 0
            contents.insert(insert_at, "iface lo inet loopback")
            changed = True

        if os.path.isdir("/etc/network/interfaces.d") and not has_source:
            contents.append("source /etc/network/interfaces.d/*")
            changed = True

        if changed:
            self._write_interfaces_file_with_backup(contents)

    def _parse_iface_block(self, interface):
        config_interface = self._resolve_iface_config_name(interface)
        lines = self._read_interface_config_lines(config_interface)
        in_block = False
        mode = None
        address = None
        netmask = None
        dns_list = []
        block_lines = []
        for line in lines:
            if re.match(r'^\s*(auto|iface)\s+{}\b'.format(re.escape(config_interface)), line):
                in_block = True
            elif in_block and re.match(r'^\s*(auto|iface)\s+\S+', line):
                break
            if not in_block:
                continue
            block_lines.append(line.rstrip("\n"))
            iface_match = re.match(r'^\s*iface\s+{}\s+inet\s+(\S+)'.format(re.escape(config_interface)), line)
            if iface_match:
                mode = iface_match.group(1)
            addr_match = re.match(r'^\s*address\s+(\S+)', line)
            if addr_match:
                address = addr_match.group(1)
            netmask_match = re.match(r'^\s*netmask\s+(\S+)', line)
            if netmask_match:
                netmask = netmask_match.group(1)
            dns_match = re.match(r'^\s*dns-nameservers\s+(.+)', line)
            if dns_match:
                dns_list = [d for d in dns_match.group(1).strip().split() if self.valid_ipv4_address(d)]
        return mode, address, netmask, dns_list, block_lines

    def _write_interfaces_file_with_backup(self, contents):
        main_path = NETWORK_INTERFACES_PATH
        try:
            _atomic_replace_text_file(main_path, "\n".join(contents) + "\n")
            return True
        except Exception as e:
            print('Failed to update interface configuration')
            print(e)
            return False

    def _ensure_iface_stanza(self, interface, expected_ip, expected_dns):
        config_interface = self._resolve_iface_config_name(interface)
        mode, address, netmask, dns_list, block_lines = self._parse_iface_block(config_interface)
        if mode:
            if mode == "static" and (not address or not netmask):
                print("Invalid interface stanza for {}: static requires address/netmask".format(interface))
                for line in block_lines:
                    print(line)
                return False
            return True

        if not expected_ip:
            print("Missing interface stanza for {} and no expected IP available".format(interface))
            return False

        addr, netmask_str = self.cidr_to_netmask(expected_ip) if "/" in expected_ip else (expected_ip, None)
        if not addr or not netmask_str:
            print("Failed to build static stanza for {} from expected IP".format(interface))
            return False

        new_block = [
            "auto {}".format(config_interface),
            "iface {} inet static".format(config_interface),
            "address {}".format(addr),
            "netmask {}".format(netmask_str),
        ]
        if expected_dns:
            new_block.append("dns-nameservers {}".format(" ".join(expected_dns)))

        lines = self._read_interface_config_lines(config_interface)
        new_lines = [l.rstrip("\n") for l in lines]
        if new_lines and new_lines[-1].strip():
            new_lines.append("")
        return self.update_interface_file(config_interface, new_block)

    def _apply_interface_config(self, interface, ip=None, gateway=None, dns_list=None):
        if interface == "mgt":
            print("Management interface cannot be modified by the generic interface editor.")
            return False
        config_interface = self._resolve_iface_config_name(interface)
        lines = self._read_interface_config_lines(config_interface)
        if dns_list is None:
            dns_list = []

        start = None
        end = None
        in_block = False
        for idx, line in enumerate(lines):
            if re.match(r'^\s*(auto|iface)\s+{}\b'.format(re.escape(config_interface)), line):
                if start is None:
                    start = idx
                    in_block = True
            elif in_block and re.match(r'^\s*(auto|iface)\s+\S+', line):
                end = idx
                in_block = False
                break
        if start is not None and end is None:
            end = len(lines)

        existing_auto = False
        existing_mode = None
        existing_address = None
        existing_netmask = None
        existing_gateway = None
        existing_dns = []
        other_lines = []

        if start is not None:
            block_lines = lines[start:end]
            for line in block_lines:
                if re.match(r'^\s*auto\s+{}\b'.format(re.escape(config_interface)), line):
                    existing_auto = True
                    continue
                iface_match = re.match(r'^\s*iface\s+{}\s+inet\s+(\S+)'.format(re.escape(config_interface)), line)
                if iface_match:
                    existing_mode = iface_match.group(1)
                    continue
                addr_match = re.match(r'^\s*address\s+(\S+)', line)
                if addr_match:
                    existing_address = addr_match.group(1)
                    continue
                netmask_match = re.match(r'^\s*netmask\s+(\S+)', line)
                if netmask_match:
                    existing_netmask = netmask_match.group(1)
                    continue
                gw_match = re.match(r'^\s*gateway\s+(\S+)', line)
                if gw_match:
                    existing_gateway = gw_match.group(1)
                    continue
                dns_match = re.match(r'^\s*dns-nameservers\s+(.+)', line)
                if dns_match:
                    existing_dns = [d for d in dns_match.group(1).strip().split() if self.valid_ipv4_address(d)]
                    continue
                other_lines.append(line.rstrip())

        if ip:
            new_address, new_netmask = self.cidr_to_netmask(ip)
            if not new_address or not new_netmask:
                print('Invalid IP address format: {}'.format(ip))
                return False
            mode = "static"
        else:
            new_address = existing_address
            new_netmask = existing_netmask
            mode = existing_mode or "static"

        new_gateway = gateway if gateway is not None else existing_gateway
        new_dns = dns_list if dns_list else existing_dns

        if start is None and not ip and (new_gateway or new_dns):
            print('IP address is required to create a new interface configuration\n')
            return False

        if mode == "static" and not new_address:
            print('IP address is required for static configuration\n')
            return False

        new_block = []
        if existing_auto or start is None:
            new_block.append("auto {}".format(config_interface))
        new_block.append("iface {} inet {}".format(config_interface, mode))

        if mode != "dhcp":
            if new_address:
                new_block.append("address {}".format(new_address))
            if new_netmask:
                new_block.append("netmask {}".format(new_netmask))
            if new_gateway:
                new_block.append("gateway {}".format(new_gateway))
        if new_dns:
            new_block.append("dns-nameservers {}".format(" ".join(new_dns)))

        for line in other_lines:
            if not line:
                continue
            if re.match(r'^\s*source\s+/etc/network/interfaces\.d/\*', line):
                continue
            if re.match(r'^\s*iface\s+lo\s+inet\s+loopback', line):
                continue
            if re.match(r'^\s*auto\s+lo\b', line):
                continue
            new_block.append(line)

        if not self.update_interface_file(config_interface, new_block):
            return False
        if dns_list:
            keep_path = self._get_interface_config_target_path(config_interface)
            self._purge_interface_dns_from_other_files(config_interface, keep_path)
        return True

    def _get_interface_config_target_path(self, interface):
        cfg_path = self._find_iface_config_path(interface)
        if cfg_path:
            return cfg_path
        return self._default_iface_config_path(interface)

    def _purge_interface_dns_from_other_files(self, interface, keep_path):
        paths = []
        main_path = "/etc/network/interfaces"
        if os.path.exists(main_path):
            paths.append(main_path)
        interfaces_d_dir = "/etc/network/interfaces.d"
        if os.path.exists(interfaces_d_dir):
            for filename in os.listdir(interfaces_d_dir):
                if filename.endswith('.cfg'):
                    paths.append(os.path.join(interfaces_d_dir, filename))

        for path in paths:
            if path == keep_path:
                continue
            try:
                with open(path, 'r') as f:
                    lines = f.readlines()
            except Exception:
                continue
            current_interface = None
            updated = []
            changed = False
            for line in lines:
                iface_match = re.match(r'^\s*(auto|iface|allow-hotplug)\s+(\S+)', line)
                if iface_match:
                    current_interface = iface_match.group(2)
                if current_interface == interface and re.match(r'^\s*dns-nameservers\s+(.+)', line):
                    changed = True
                    continue
                updated.append(line)
            if changed:
                try:
                    _atomic_replace_text_file(path, "".join(updated))
                except Exception:
                    continue

    def set_interface_callback2(self, param):
        status = 0
        output = None
        if param and param[0] == "mgt":
            print("Management interface cannot be modified by the generic interface callback.")
            return False
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
                            print("DHCP does not require an explicit address")
                        elif new_address:
                            contents.append("address {0}".format(new_address))
                            iface_configured = True
                        else:
                            contents.append(line)
                    # Matching the netmask line
                    elif re.match("\s*netmask\s+(.*)", line):
                        if network_mode == "dhcp":
                            print("DHCP does not require an explicit address")
                        elif new_netmask:
                            contents.append("netmask {0}".format(new_netmask))
                            netmask_configured = True
                            iface_configured = True
                        else:
                            contents.append(line)
                    # Matching the gateway line
                    elif re.match("\s*gateway\s+.*", line):
                        if network_mode == "dhcp":
                            print("DHCP does not require an explicit address")
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
            if not self.write_full_interfaces_file(contents):
                status = 1
                return
            if field.lower() == "restart":
                print('Restarting network interface. You need to use new IP address to reconnect...\n')
                if not self._restart_interface_with_verification(interface):
                    status = 1
                    return
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
                print('Please configure IP address and netmask before configuring "{}" interface gateway'.format(interface))
                print('set interface {} ip <IP Address/Netmask>\n'.format(interface))
                return
            self.update_dp_mgt_data(new_gateway, interface) 

        elif require_interface_restart:
             print("Restarting network interface. You need to use new IP address to reconnect...\n")
             self._restart_interface_with_verification(interface)

        if not (field.lower() == "restart"):
             print("Run 'set interface {0} restart' command to apply the changes.\n".format(interface))

        return None

    def _restart_interface_with_verification(self, interface):
        if interface == "mgt":
            return self._restart_mgt_interface()
        expected_ip, expected_dns = self._get_interface_expected_config(interface)
        expected_gateway = self._get_interface_gateway(interface)
        self._ensure_interfaces_base()
        if not self._ensure_iface_stanza(interface, expected_ip, expected_dns):
            return False

        dry_run = subprocess.run(
            "ifup --no-act {}".format(interface),
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if dry_run.returncode != 0:
            print("ifup dry-run failed for {}".format(interface))
            print("returncode: {}".format(dry_run.returncode))
            if dry_run.stdout:
                print("stdout: {}".format(dry_run.stdout.strip()))
            if dry_run.stderr:
                print("stderr: {}".format(dry_run.stderr.strip()))
            return False

        if not self.restart_new_network_manager(interface, expected_ip=expected_ip, expected_dns=expected_dns):
            return False

        if expected_gateway and self.is_sensor_host_mode():
            if not self._ensure_host_gateway(interface, expected_gateway):
                return False

        print("Restart completed.\n")
        return True

    def _ensure_host_gateway(self, interface, gateway):
        cmd_show = "ip route show default"
        proc = subprocess.Popen(cmd_show, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        out, _ = proc.communicate()
        if out:
            m = re.search(r'default\s+via\s+(\d+\.\d+\.\d+\.\d+)\s+dev\s+(\S+)', out.decode('utf-8', errors='ignore'))
            if m and m.group(1) == gateway and m.group(2) == interface:
                return True

        cmd_set = "ip route replace default via {} dev {}".format(gateway, interface)
        set_proc = subprocess.run(cmd_set, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if set_proc.returncode != 0:
            err_msg = set_proc.stderr.strip() if set_proc.stderr else set_proc.stdout.strip()
            err_msg = err_msg if err_msg else "Unknown error"
            print("Failed to apply host gateway: {}".format(err_msg))
            return False

        proc = subprocess.Popen(cmd_show, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        out, _ = proc.communicate()
        if out:
            m = re.search(r'default\s+via\s+(\d+\.\d+\.\d+\.\d+)\s+dev\s+(\S+)', out.decode('utf-8', errors='ignore'))
            if m and m.group(1) == gateway and m.group(2) == interface:
                return True

        print("Failed to verify host default gateway")
        return False

    def restart_new_network_manager(self, interface, expected_ip=None, expected_dns=None):
        if interface == "mgt":
            return self._restart_mgt_interface()
        try:
            rm_proc = subprocess.run(
                "rm -f /run/resolvconf/interface/{0}.dhclient".format(interface),
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            flush_proc = subprocess.run(
                "ip address flush dev {0}".format(interface),
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if flush_proc.returncode != 0:
                err_msg = flush_proc.stderr.strip() if flush_proc.stderr else flush_proc.stdout.strip()
                err_msg = err_msg if err_msg else "Unknown error"
                print("Failed to restart networking! {}".format(err_msg))
                return False
            down_proc = subprocess.run(
                "ifdown {0}".format(interface),
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            up_proc = subprocess.run(
                "ifup {0}".format(interface),
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if up_proc.returncode != 0:
                err_text = "{}\n{}".format(up_proc.stdout or "", up_proc.stderr or "")
                if expected_ip and ("File exists" in err_text or "Address already assigned" in err_text):
                    print("Warning: ifup returned address already assigned; continuing with state verification")
                else:
                    print("Failed to restart networking!")
                    print("returncode: {}".format(up_proc.returncode))
                    if up_proc.stdout:
                        print("stdout: {}".format(up_proc.stdout.strip()))
                    if up_proc.stderr:
                        print("stderr: {}".format(up_proc.stderr.strip()))
                    return False
        except Exception as e:
            print("Failed to restart networking! {}".format(e))
            return False

        addr_out = subprocess.run(
            "ip -4 addr show dev {}".format(interface),
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        inet_lines = []
        if addr_out.returncode == 0 and addr_out.stdout:
            inet_lines = re.findall(r'\binet\s+(\d+\.\d+\.\d+\.\d+/\d+)', addr_out.stdout)
        if len(inet_lines) == 0 and expected_ip:
            add_proc = subprocess.run(
                "ip -4 addr add {} dev {}".format(expected_ip, interface),
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if add_proc.returncode != 0:
                err_msg = add_proc.stderr.strip() if add_proc.stderr else add_proc.stdout.strip()
                err_msg = err_msg if err_msg else "Unknown error"
                print("Failed to recover IP address on {}: {}".format(interface, err_msg))
                return False
            addr_out = subprocess.run(
                "ip -4 addr show dev {}".format(interface),
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            inet_lines = re.findall(r'\binet\s+(\d+\.\d+\.\d+\.\d+/\d+)', addr_out.stdout or "")
            if len(inet_lines) != 1 or expected_ip not in inet_lines:
                print("Failed to verify IPv4 address count on {} after recovery".format(interface))
                return False
        if len(inet_lines) > 1:
            if not expected_ip:
                print("Multiple IPv4 addresses detected on {} after restart".format(interface))
                return False
            subprocess.run(
                "ip -4 addr flush dev {}".format(interface),
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            add_proc = subprocess.run(
                "ip -4 addr add {} dev {}".format(expected_ip, interface),
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if add_proc.returncode != 0:
                err_msg = add_proc.stderr.strip() if add_proc.stderr else "Unknown error"
                print("Failed to recover IP address on {}: {}".format(interface, err_msg))
                return False
            addr_out = subprocess.run(
                "ip -4 addr show dev {}".format(interface),
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            inet_lines = re.findall(r'\binet\s+(\d+\.\d+\.\d+\.\d+/\d+)', addr_out.stdout or "")
            if len(inet_lines) != 1 or expected_ip not in inet_lines:
                print("Failed to verify IPv4 address count on {} after recovery".format(interface))
                return False

        if expected_ip:
            check_proc = subprocess.run(
                "ip -4 addr show dev {}".format(interface),
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if check_proc.returncode != 0 or expected_ip not in check_proc.stdout:
                print("Failed to verify IP address on {} after restart".format(interface))
                return False

        if expected_dns:
            current_dns = self._get_interface_expected_config(interface)[1]
            if not set(expected_dns).issubset(set(current_dns)):
                print("Failed to verify DNS settings on {} after restart".format(interface))
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
        filtered = [p for p in param if p != ""]
        if filtered and filtered[0].rstrip("?") == "mgt":
            if filtered[0].endswith("?") or len(filtered) == 1:
                print('\nip <IP Address/Netmask>   Specify interface IP address and netmask')
                print('gateway <IP Address>      Specify default gateway IP address')
                print('dns <IP Address> [...]    Specify DNS server IP address(es)')
                print('restart                   Restart network interface\n')
                return
            self._set_mgt_interface(filtered)
            return
        if self.is_sensor_host_mode():
            self.set_interface_sensor(param)
            return

        self._debug_print("DEBUG set interface param={}".format(param))
        param = [p for p in param if p != '']

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
                print('dns <IP Address> [...]    Specify DNS server IP address or addresses separated by space')
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
                print('\n<IP Address> [...]    Specify DNS server IP address or addresses separated by space\n')
                return
            elif (len(param) == 2 and param[1].endswith('restart?')) or \
                (len(param) == 3 and param[1] == 'restart' and param[2].endswith('?')):
                print('\nPress [Enter]\n')
                return
            elif (len(param) == 3 and param[1] == 'ip' and self.valid_ipv4_address(param[2].rstrip('?')) and param[2].endswith('?')) or \
                (len(param) == 4 and param[1] == 'ip' and self.valid_ipv4_address(param[2]) and param[3] == '?'):
                print('\nPress [Enter]\n')
                return
            elif (len(param) == 3 and param[1] == 'gateway' and self.valid_ipv4_address(param[2].rstrip('?')) and param[2].endswith('?')) or \
                (len(param) == 4 and param[1] == 'gateway' and self.valid_ipv4_address(param[2]) and param[3] == '?'):
                if not (re.match('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', param[2]) or \
                    re.match('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', param[2].rstrip('?'))):
                    print('Invalid gateway IP address format:')
                    print('\n<IP Address>      Specify default gateway IP address\n')
                    return
                print('\nPress [Enter]\n') 
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
            # Allow user-selected interfaces without hardcoding
            self.set_interface_sensor(param)
            return
        # DP Appliance does NOT support dhcp on any interfaces
        #if option == 'dns' and (interface == 'data0'):
        #    print('Invalid option: only "mgt" interface support dns option')
        #    return

        if not self.is_device_exist(interface):
           return

        if len(param) >= 2 and param[1] == 'restart':
            print('Restarting network interface. You need to use new IP address to reconnect...\n')
            self._restart_interface_with_verification(interface)
            return

        tokens = [t for t in param[1:]]
        keywords = [t.lower() for t in tokens if t.lower() in {"ip", "gateway", "dns", "restart"}]
        if len(keywords) > 1 or ("restart" in keywords and len(tokens) > 1):
            try:
                parsed = self._parse_set_interface_args(tokens)
            except ValueError as e:
                print('{}\n'.format(e))
                return

            if parsed["ip"]:
                if parsed["ip"] == 'dhcp':
                    print("Invalid ip option: DHCP client is not supported")
                    return
                if '/' not in parsed["ip"] and self.valid_ipv4_address(parsed["ip"]):
                    print('Please specify network mask: {0}'.format(parsed["ip"]))
                    return
                if not self.valid_ipv4_address(parsed["ip"]) or '/' not in parsed["ip"]:
                    print('Invalid IP address format: {0}'.format(parsed["ip"]))
                    return
            if parsed["gateway"]:
                if not self.valid_ipv4_address(parsed["gateway"]) or '/' in parsed["gateway"]:
                    print('Invalid gateway IP address format: {0}'.format(parsed["gateway"]))
                    return
            if parsed["dns"]:
                if interface != 'mgt':
                    print('Invalid option: Only "mgt" interface support dns option')
                    return
                for dns in parsed["dns"]:
                    if not self.valid_ipv4_address(dns):
                        print('Invalid DNS server IP address format: {0}'.format(dns))
                        return

            if not self._apply_interface_config(
                interface,
                ip=parsed["ip"],
                gateway=parsed["gateway"],
                dns_list=parsed["dns"],
            ):
                return

            if parsed["restart"]:
                print('Restarting network interface. You need to use new IP address to reconnect...\n')
                if not self._restart_interface_with_verification(interface):
                    return
            else:
                print("Run 'set interface {0} restart' command to apply the changes.\n".format(interface))
            return

        if option != 'ip' and option != 'gateway' and option != 'dns' and option != 'restart':
            print('Invalid option: {0}'.format(option))
            return
        if option == 'ip':
            #if ip_address != 'dhcp' and len(ip_address.split('.')) < 4:
            if ip_address != 'dhcp' and '/' not in ip_address and self.valid_ipv4_address(ip_address):
                print('Please specify network mask: {0}'.format(ip_address))
                return
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
                    print('\nPress [Enter]\n')
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
        options = ['ip', 'gateway', 'dns', 'restart']
        prefix_tokens = line[:begidx].split()
        # Expect: set interface <iface> [option]
        if len(prefix_tokens) >= 3:
            completion_set = options
        else:
            completion_set = self._get_interface_completion_list()

        if not text:
            completions = completion_set
        else:
            completions = [f for f in completion_set if f.startswith(text)]
        return completions

    def complete_unset_interface(self, text, line, begidx, endidx):
        options = ['ip', 'gateway', 'restart']
        prefix_tokens = line[:begidx].split()
        # Expect: unset interface <iface> [option]
        if len(prefix_tokens) >= 3:
            completion_set = options
        else:
            completion_set = self._get_interface_completion_list()

        if not text:
            completions = completion_set
        else:
            completions = [f for f in completion_set if f.startswith(text)]
        return completions

    def complete_show_interface(self, text, line, begidx, endidx):
        completion_set = self._get_interface_completion_list()
        if not text:
            return completion_set
        return [f for f in completion_set if f.startswith(text)]

    def _get_interface_completion_list(self):
        interfaces = os.listdir('/sys/class/net/')
        if 'virbr0' in interfaces:
            interfaces.remove('virbr0')
        if 'virbr0-nic' in interfaces:
            interfaces.remove('virbr0-nic')
        # Allow CLI aliases even if not kernel interfaces
        try:
            if self._interface_block_exists("host") or self._interface_block_exists("hostmgmt"):
                interfaces.append("host")
            if self._interface_block_exists("hostmgmt"):
                interfaces.append("hostmgmt")
        except Exception:
            pass
        return interfaces

    def complete_set(self, text, line, begidx, endidx):
        if not text and not line.startswith('set'):
            completions = self.set_command_help.keys()
        elif line.startswith('set interface'):
            return self.complete_set_interface(text, line, begidx, endidx)
        elif line.startswith('set dns'):
            return self.complete_set_dns(text, line, begidx, endidx)
        else:
            completions = [f for f in self.set_command_help.keys() if f.startswith(text)]
        return completions

    def complete_set_dns(self, text, line, begidx, endidx):
        tokens = line.split()
        # Expect: set dns <iface> [dns...]
        if len(tokens) <= 2:
            completion_set = self._get_interface_completion_list()
        else:
            # DNS values are free-form IPs; no safe completion
            completion_set = []
        if not text:
            return completion_set
        return [f for f in completion_set if f.startswith(text)]

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