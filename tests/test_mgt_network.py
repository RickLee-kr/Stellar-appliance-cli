import contextlib
import io
import inspect
import logging.handlers
import os
import re
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

with mock.patch.object(logging.handlers.RotatingFileHandler, "__init__", return_value=None), \
     mock.patch.object(Path, "mkdir", return_value=None):
    import appliance_cli as module


BASE = (
    "# topology\n"
    "auto bond0\n"
    "iface bond0 inet manual\n"
    "\n"
    "auto mgt\n"
    "iface mgt inet static\n"
    "    address 10.0.0.2\n"
    "    netmask 255.255.255.0\n"
    "    gateway 10.0.0.1\n"
    "    dns-nameservers 1.1.1.1\n"
    "    bond-mode active-backup\n"
    "    bond-miimon 100\n"
    "    bond-primary mgtpri\n"
    "    bond-slaves mgtpri mgtbak\n"
    "    pre-up /usr/local/bin/preserve-this\n"
    "    # keep me\n"
)


class ManagementNetworkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.main = root / "interfaces"
        self.directory = root / "interfaces.d"
        self.directory.mkdir()
        self.canonical = self.directory / "01-mgt.cfg"
        self.main.write_text("auto lo\niface lo inet loopback\n", encoding="utf-8")
        self.canonical.write_text(BASE, encoding="utf-8")
        self.cli = module.AellaCli.__new__(module.AellaCli)
        self.patches = [
            mock.patch.object(module, "MGT_CONFIG_PATH", str(self.canonical)),
            mock.patch.object(module, "NETWORK_INTERFACES_PATH", str(self.main)),
            mock.patch.object(module, "NETWORK_INTERFACES_DIR", str(self.directory)),
        ]
        for patcher in self.patches:
            patcher.start()

    def tearDown(self):
        for patcher in reversed(self.patches):
            patcher.stop()
        self.temp.cleanup()

    def test_01_constants(self):
        self.assertTrue(module.MGT_CONFIG_PATH.endswith("01-mgt.cfg"))

    def test_02_atomic_preserves_mode(self):
        os.chmod(self.canonical, 0o640)
        module._atomic_replace_text_file(self.canonical, "new\n")
        self.assertEqual(stat.S_IMODE(os.stat(self.canonical).st_mode), 0o640)

    def test_03_atomic_leaves_no_backup_or_temp(self):
        module._atomic_replace_text_file(self.canonical, "new\n")
        self.assertEqual(sorted(p.name for p in self.directory.iterdir()), ["01-mgt.cfg"])

    def test_04_update_address_and_cidr_mask(self):
        rendered = self.cli._render_mgt_ipv4_config(
            BASE, address="10.0.1.2", netmask="24"
        )
        self.assertIn("address 10.0.1.2", rendered)
        self.assertIn("netmask 255.255.255.0", rendered)

    def test_05_dotted_netmask(self):
        rendered = self.cli._render_mgt_ipv4_config(BASE, netmask="255.255.0.0")
        self.assertIn("netmask 255.255.0.0", rendered)

    def test_06_invalid_noncontiguous_netmask(self):
        with self.assertRaises(ValueError):
            self.cli._render_mgt_ipv4_config(BASE, netmask="255.0.255.0")

    def test_07_none_is_unchanged(self):
        self.assertEqual(self.cli._render_mgt_ipv4_config(BASE), BASE)

    def test_08_remove_gateway(self):
        rendered = self.cli._render_mgt_ipv4_config(BASE, remove_gateway=True)
        self.assertNotIn("gateway 10.0.0.1", rendered)

    def test_09_remove_dns(self):
        rendered = self.cli._render_mgt_ipv4_config(BASE, remove_dns=True)
        self.assertNotIn("dns-nameservers", rendered)

    def test_10_insert_dns_preserves_unknown_lines(self):
        source = BASE.replace("    dns-nameservers 1.1.1.1\n", "")
        rendered = self.cli._render_mgt_ipv4_config(
            source, dns_nameservers=["8.8.8.8", "8.8.4.4"]
        )
        self.assertIn("    bond-slaves mgtpri mgtbak\n", rendered)
        self.assertIn("dns-nameservers 8.8.8.8 8.8.4.4", rendered)

    def test_10b_active_passive_topology_is_byte_preserved(self):
        rendered = self.cli._render_mgt_ipv4_config(BASE, gateway="10.0.0.9")
        for line in (
            "    bond-mode active-backup\n",
            "    bond-miimon 100\n",
            "    bond-primary mgtpri\n",
            "    bond-slaves mgtpri mgtbak\n",
            "    pre-up /usr/local/bin/preserve-this\n",
        ):
            self.assertEqual(rendered.count(line), 1)

    def test_11_missing_static_stanza_fails(self):
        with self.assertRaises(ValueError):
            self.cli._render_mgt_ipv4_config("auto mgt\niface mgt inet dhcp\n")

    def test_12_multiple_static_stanzas_fail(self):
        with self.assertRaises(ValueError):
            self.cli._render_mgt_ipv4_config(BASE + "\niface mgt inet static\n")

    def test_13_cleanup_stale_stanza_and_activation_token(self):
        source = (
            "auto eth0 mgt # keep\nallow-hotplug eth1 mgt\n"
            "iface mgt inet static\n address 1.2.3.4\n"
            "iface mgt inet dhcp\n"
            "iface eth0 inet dhcp\n"
        )
        rendered, changed = self.cli._remove_mgt_from_noncanonical_text(source)
        self.assertTrue(changed)
        self.assertIn("auto eth0 # keep", rendered)
        self.assertNotIn("iface mgt inet static", rendered)
        self.assertIn("iface mgt inet dhcp", rendered)
        self.assertIn("allow-hotplug eth1", rendered)

    def test_14_transaction_cleans_stale_before_canonical(self):
        stale = self.directory / "99-old.cfg"
        stale.write_text("auto mgt\niface mgt inet static\n address 1.2.3.4\n", encoding="utf-8")
        events = []
        real_prepare = module._prepare_atomic_text_file
        real_commit = module._commit_prepared_text_file

        def prepare(path, text):
            events.append(("prepare", os.fspath(path)))
            return real_prepare(path, text)

        def commit(path, temporary_path):
            events.append(("commit", os.fspath(path)))
            return real_commit(path, temporary_path)

        with mock.patch.object(module, "_prepare_atomic_text_file", side_effect=prepare), \
             mock.patch.object(module, "_commit_prepared_text_file", side_effect=commit):
            self.assertTrue(self.cli._apply_mgt_transaction(gateway="10.0.0.9"))
        self.assertEqual(
            events,
            [
                ("prepare", str(stale)),
                ("prepare", str(self.canonical)),
                ("commit", str(stale)),
                ("commit", str(self.canonical)),
            ],
        )
        self.assertFalse(any(path.name.startswith(".") for path in self.directory.iterdir()))

    def test_15_transaction_rolls_back_on_canonical_failure(self):
        stale = self.directory / "99-old.cfg"
        stale_text = "auto mgt\niface mgt inet static\n address 1.2.3.4\n"
        stale.write_text(stale_text, encoding="utf-8")
        real_commit = module._commit_prepared_text_file

        def fail_canonical(path, temporary_path):
            if os.fspath(path) == str(self.canonical):
                raise module._AtomicCommitError(OSError("boom"), replaced=False)
            return real_commit(path, temporary_path)

        with mock.patch.object(
            module, "_commit_prepared_text_file", side_effect=fail_canonical
        ):
            self.assertFalse(self.cli._apply_mgt_transaction(gateway="10.0.0.9"))
        self.assertEqual(stale.read_text(encoding="utf-8"), stale_text)
        self.assertEqual(self.canonical.read_text(encoding="utf-8"), BASE)
        self.assertFalse(any(path.name.startswith(".") for path in self.directory.iterdir()))

    def test_16_noop_does_not_write(self):
        with mock.patch.object(module, "_prepare_atomic_text_file") as prepare, \
             mock.patch.object(module, "_commit_prepared_text_file") as commit:
            self.assertTrue(self.cli._apply_mgt_transaction())
        prepare.assert_not_called()
        commit.assert_not_called()

    def test_17_restart_uses_only_expected_mutating_commands(self):
        results = [
            mock.Mock(returncode=0, stdout="", stderr=""),
            mock.Mock(returncode=0, stdout="", stderr=""),
            mock.Mock(returncode=0, stdout="", stderr=""),
            mock.Mock(returncode=0, stdout="inet 10.0.0.2/24", stderr=""),
            mock.Mock(returncode=0, stdout="default via 10.0.0.1 dev mgt", stderr=""),
        ]
        with mock.patch.object(module.subprocess, "run", side_effect=results) as run:
            self.assertTrue(self.cli._restart_mgt_interface())
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(commands[:3], [
            ["ifup", "--no-act", "mgt"],
            ["sudo", "ifdown", "--force", "mgt"],
            ["sudo", "ifup", "mgt"],
        ])
        self.assertFalse(any("flush" in command or "table 1" in command for command in map(str, commands)))

    def test_18_dry_run_failure_stops_restart(self):
        result = mock.Mock(returncode=1, stdout="", stderr="bad")
        with mock.patch.object(module.subprocess, "run", return_value=result) as run:
            self.assertFalse(self.cli._restart_mgt_interface())
        self.assertEqual(run.call_count, 1)

    def test_19_restart_failure_rolls_back_setting(self):
        before = self.canonical.read_text(encoding="utf-8")
        with mock.patch.object(self.cli, "_restart_mgt_interface", return_value=False):
            self.assertFalse(self.cli._apply_mgt_transaction(restart=True, gateway="10.0.0.9"))
        self.assertEqual(self.canonical.read_text(encoding="utf-8"), before)

    def test_20_show_dns_only_reads_canonical(self):
        real_open = open

        def guarded_open(path, *args, **kwargs):
            self.assertNotEqual(os.fspath(path), "/etc/resolv.conf")
            return real_open(path, *args, **kwargs)

        with mock.patch("builtins.open", side_effect=guarded_open), \
             mock.patch.object(module.subprocess, "Popen") as popen:
            status, output = self.cli.show_dns_callback("dns", [])
        self.assertEqual(status, 0)
        self.assertIn("1.1.1.1", output)
        self.assertIn("Configuration source:\n  {}".format(self.canonical), output)
        popen.assert_not_called()

    def test_21_mgt_precedes_sensor_detection(self):
        with mock.patch.object(self.cli, "_set_mgt_interface") as setter, \
             mock.patch.object(self.cli, "is_sensor_host_mode", return_value=True):
            self.cli.set_interface_callback("interface", ["mgt", "dns", "8.8.8.8"])
        setter.assert_called_once()

    def test_22_generic_update_rejects_mgt(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(self.cli.update_interface_file("mgt", ["auto mgt"]))

    def test_23_direct_update_uses_full_transaction(self):
        stale = self.directory / "stale.cfg"
        stale.write_text("auto mgt eth0\niface mgt inet static\n address 2.2.2.2\n")
        self.assertTrue(self.cli._update_mgt_ipv4_config(
            ip_cidr="10.2.3.4/24",
            gateway="10.2.3.1",
            dns_servers=["9.9.9.9"],
        ))
        text = self.canonical.read_text()
        self.assertIn("address 10.2.3.4", text)
        self.assertIn("gateway 10.2.3.1", text)
        self.assertIn("dns-nameservers 9.9.9.9", text)
        self.assertNotIn("iface mgt inet static", stale.read_text())

    def test_24_composite_callback_updates_and_reports_success(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), \
             mock.patch.object(self.cli, "is_sensor_host_mode", return_value=True):
            self.cli.set_interface_callback(
                "interface",
                ["mgt", "ip", "10.8.0.2/24", "gateway", "10.8.0.1",
                 "dns", "8.8.8.8", "8.8.4.4"],
            )
        self.assertIn("Configuration updated successfully.", output.getvalue())
        self.assertIn("Run 'set interface mgt restart' to apply the changes.", output.getvalue())
        text = self.canonical.read_text()
        self.assertIn("address 10.8.0.2", text)
        self.assertIn("gateway 10.8.0.1", text)
        self.assertIn("dns-nameservers 8.8.8.8 8.8.4.4", text)

    def test_25_set_dns_callback_success_and_failure_messages(self):
        success = io.StringIO()
        with contextlib.redirect_stdout(success):
            self.cli.set_dns_callback("dns", ["mgt", "9.9.9.9"])
        self.assertIn("Configuration updated successfully.", success.getvalue())
        self.assertIn("Run 'set interface mgt restart' to apply the changes.", success.getvalue())

        failure = io.StringIO()
        self.canonical.unlink()
        with contextlib.redirect_stdout(failure):
            self.cli.set_dns_callback("dns", ["mgt", "8.8.8.8"])
        self.assertNotIn("success", failure.getvalue().lower())
        self.assertIn("Management configuration not found:", failure.getvalue())

    def test_26_no_dns_exact_output(self):
        self.canonical.write_text(BASE.replace("    dns-nameservers 1.1.1.1\n", ""))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status, rendered = self.cli.show_dns_callback("dns", [])
        self.assertEqual(status, 0)
        self.assertEqual(rendered, "No DNS servers configured for mgt")

    def test_27_generic_callbacks_cannot_modify_mgt(self):
        before = self.canonical.read_text()
        with contextlib.redirect_stdout(io.StringIO()):
            result = self.cli.set_interface_callback2(["mgt", "dns", "8.8.8.8"])
            applied = self.cli._apply_interface_config("mgt", gateway="10.0.0.9")
        self.assertFalse(result)
        self.assertFalse(applied)
        self.assertEqual(self.canonical.read_text(), before)

    def test_28_sensor_non_mgt_changes_are_rejected_exactly(self):
        expected = (
            "Host IP configuration is not managed by this CLI in Sensor bridge mode.\n"
            "Configure the Sensor VM management IP inside the Sensor VM.\n"
        )
        for args in (
            ["eth0", "ip", "10.0.0.2/24"],
            ["eth0", "gateway", "10.0.0.1"],
            ["eth0", "dns", "8.8.8.8"],
            ["eth0", "restart"],
        ):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.cli.set_interface_sensor(args)
            self.assertEqual(output.getvalue(), expected)

    def test_29_restart_callback_has_no_forbidden_runtime_operations(self):
        results = [
            mock.Mock(returncode=0, stdout="", stderr=""),
            mock.Mock(returncode=0, stdout="", stderr=""),
            mock.Mock(returncode=0, stdout="", stderr=""),
            mock.Mock(returncode=0, stdout="inet 10.0.0.2/24", stderr=""),
            mock.Mock(returncode=0, stdout="default via 10.0.0.1 dev mgt", stderr=""),
        ]
        output = io.StringIO()
        with contextlib.redirect_stdout(output), \
             mock.patch.object(module.subprocess, "run", side_effect=results) as run:
            self.cli.set_interface_callback("interface", ["mgt", "restart"])
        commands = "\n".join(map(str, (call.args[0] for call in run.call_args_list)))
        for forbidden in ("table 1", "flush", "addr add", "resolvconf", "MASQUERADE", "ip rule"):
            self.assertNotIn(forbidden, commands)
        self.assertIn("Management interface restarted successfully.", output.getvalue())
        self.assertNotIn("Configuration updated successfully.", output.getvalue())

    def test_30_gateway_and_dns_updates_preserve_each_other(self):
        self.cli.set_interface_callback("interface", ["mgt", "gateway", "10.0.0.9"])
        after_gateway = self.canonical.read_text()
        self.assertIn("dns-nameservers 1.1.1.1", after_gateway)
        self.cli.set_interface_callback("interface", ["mgt", "dns", "8.8.8.8"])
        after_dns = self.canonical.read_text()
        self.assertIn("gateway 10.0.0.9", after_dns)
        self.assertIn("dns-nameservers 8.8.8.8", after_dns)

    def test_31_transaction_rejects_missing_and_multiple_canonical(self):
        output = io.StringIO()
        self.canonical.unlink()
        with contextlib.redirect_stdout(output):
            self.assertFalse(self.cli._update_mgt_ipv4_config(gateway="10.0.0.9"))
        self.assertIn(
            "Management configuration not found: {}".format(self.canonical),
            output.getvalue(),
        )
        self.canonical.write_text(BASE + "\niface mgt inet static\n")
        with mock.patch.object(module, "_prepare_atomic_text_file") as prepare:
            self.assertFalse(self.cli._update_mgt_ipv4_config(gateway="10.0.0.9"))
        prepare.assert_not_called()

    def test_32_composite_restart_failure_rolls_back_callback(self):
        before = self.canonical.read_text()
        output = io.StringIO()
        with contextlib.redirect_stdout(output), \
             mock.patch.object(self.cli, "_restart_mgt_interface", return_value=False):
            self.cli.set_interface_callback(
                "interface",
                ["mgt", "gateway", "10.0.0.9", "restart"],
            )
        self.assertEqual(self.canonical.read_text(), before)
        self.assertNotIn("success", output.getvalue().lower())

    def test_33_noop_callback_has_no_success_message(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.cli.set_interface_callback(
                "interface", ["mgt", "gateway", "10.0.0.1"]
            )
        self.assertNotIn("success", output.getvalue().lower())
        self.assertNotIn("Run 'set interface mgt restart'", output.getvalue())

    def test_34_mgt_restart_source_has_no_forbidden_operations(self):
        source = inspect.getsource(self.cli._restart_mgt_interface)
        for forbidden in (
            "table 1", "addr add", "address flush", "resolvconf",
            "MASQUERADE", "ip rule", '"rt_mgt"',
        ):
            self.assertNotIn(forbidden, source)
        self.assertFalse(hasattr(self.cli, "_ensure_mgt_gateway"))

    def test_35_second_prepare_failure_replaces_nothing(self):
        stale = self.directory / "99-old.cfg"
        stale_original = "auto mgt\niface mgt inet static\n address 1.2.3.4\n"
        stale.write_text(stale_original)
        real_prepare = module._prepare_atomic_text_file
        calls = {"count": 0}

        def fail_second(path, text):
            calls["count"] += 1
            if calls["count"] == 2:
                raise OSError("prepare failed")
            return real_prepare(path, text)

        with mock.patch.object(
            module, "_prepare_atomic_text_file", side_effect=fail_second
        ), mock.patch.object(module, "_commit_prepared_text_file") as commit:
            self.assertFalse(self.cli._apply_mgt_transaction(gateway="10.0.0.9"))
        commit.assert_not_called()
        self.assertEqual(stale.read_text(), stale_original)
        self.assertEqual(self.canonical.read_text(), BASE)
        self.assertEqual(
            sorted(path.name for path in self.directory.iterdir()),
            ["01-mgt.cfg", "99-old.cfg"],
        )

    def test_36_sensor_unset_rejected_and_mgt_stays_canonical(self):
        expected = (
            "Host IP configuration is not managed by this CLI in Sensor bridge mode.\n"
            "Configure the Sensor VM management IP inside the Sensor VM.\n"
        )
        for option in ("ip", "gateway", "restart"):
            output = io.StringIO()
            with contextlib.redirect_stdout(output), \
                 mock.patch.object(self.cli, "is_sensor_host_mode", return_value=True):
                self.cli.unset_interface_callback("interface", ["eth0", option])
            self.assertEqual(output.getvalue(), expected)

        self.cli._mgt_last_changed = False
        with mock.patch.object(self.cli, "is_sensor_host_mode", return_value=True), \
             mock.patch.object(self.cli, "unset_interface_sensor") as sensor_unset, \
             mock.patch.object(self.cli, "_apply_mgt_transaction", return_value=True) as apply:
            self.cli.unset_interface_callback("interface", ["mgt", "gateway"])
        sensor_unset.assert_not_called()
        apply.assert_called_once_with(remove_gateway=True)

    def test_37_duplicate_directives_are_normalized_for_every_change(self):
        duplicate = BASE.replace(
            "    address 10.0.0.2\n",
            "    address 10.0.0.2\n\taddress 10.0.0.3\r\n",
        ).replace(
            "    netmask 255.255.255.0\n",
            "    netmask 255.255.255.0\n  netmask 255.255.0.0\n",
        ).replace(
            "    gateway 10.0.0.1\n",
            "    gateway 10.0.0.1\n gateway 10.0.0.254\n",
        ).replace(
            "    dns-nameservers 1.1.1.1\n",
            "    dns-nameservers 1.1.1.1\n dns-nameservers 9.9.9.9\n",
        )
        rendered = self.cli._render_mgt_ipv4_config(
            duplicate, address="10.8.0.2", netmask="24"
        )
        self.assertEqual(len(re.findall(r"(?m)^\s*address\s+", rendered)), 1)
        self.assertEqual(len(re.findall(r"(?m)^\s*netmask\s+", rendered)), 1)
        self.assertEqual(len(re.findall(r"(?m)^\s*gateway\s+", rendered)), 1)
        self.assertEqual(len(re.findall(r"(?m)^\s*dns-nameservers\s+", rendered)), 1)
        self.assertIn("address 10.8.0.2", rendered)
        self.assertNotIn("address 10.0.0.2", rendered)
        self.assertNotIn("address 10.0.0.3", rendered)
        self.assertIn("    gateway 10.0.0.1\n", rendered)
        self.assertNotIn("gateway 10.0.0.254", rendered)

        gateway = self.cli._render_mgt_ipv4_config(
            duplicate, gateway="10.0.0.9"
        )
        self.assertEqual(len(re.findall(r"(?m)^\s*gateway\s+", gateway)), 1)
        self.assertIn("gateway 10.0.0.9", gateway)
        removed = self.cli._render_mgt_ipv4_config(
            duplicate, remove_gateway=True, remove_dns=True
        )
        self.assertNotRegex(removed, r"(?m)^\s*(gateway|dns-nameservers)\s+")

    def test_38_callbacks_preserve_active_passive_fixture_exactly(self):
        topology = (
            "# leading\r\n"
            "auto mgtpri\r\niface mgtpri inet manual\r\n\tbond-master mgt\r\n"
            "\r\n# backup\r\n"
            "auto mgtbak\r\niface mgtbak inet manual\r\n  bond-master mgt\r\n"
            "\r\n"
            "auto mgt\r\niface mgt inet static\r\n"
            "\taddress 10.0.0.2\r\n\tnetmask 255.255.255.0\r\n"
            "\tgateway 10.0.0.1\r\n\tdns-nameservers 1.1.1.1\r\n"
            "\tbond-mode active-backup\r\n\tbond-primary mgtpri\r\n"
            "\tbond-slaves mgtpri mgtbak\r\n\tunknown-option  value\r\n"
            "\t# inside\r\n"
        )
        preserved = [
            line for line in topology.splitlines(keepends=True)
            if not re.match(r"^\s*(address|netmask|gateway|dns-nameservers)\s+", line)
        ]
        for args in (
            ["mgt", "ip", "10.0.0.8/24"],
            ["mgt", "gateway", "10.0.0.9"],
            ["mgt", "dns", "8.8.8.8"],
        ):
            with open(self.canonical, "w", encoding="utf-8", newline="") as stream:
                stream.write(topology)
            self.cli.set_interface_callback("interface", args)
            with open(self.canonical, "r", encoding="utf-8", newline="") as stream:
                after = stream.read()
            actual = [
                line for line in after.splitlines(keepends=True)
                if not re.match(r"^\s*(address|netmask|gateway|dns-nameservers)\s+", line)
            ]
            self.assertEqual(actual, preserved)

    def test_39_transaction_removes_all_stale_static_definitions(self):
        main_text = (
            "# main\nsource /etc/network/interfaces.d/*.cfg\n\n"
            "auto lo mgt eth0 # shared\nallow-hotplug mgt eth1\n"
            "iface lo inet loopback\niface eth0 inet dhcp\n"
            "iface mgt inet static\n address 192.0.2.2\n"
            "iface mgtpri inet manual\n bond-master mgt\n"
        )
        stale_one = self.directory / "10-stale.cfg"
        stale_two = self.directory / "20-stale.cfg"
        self.main.write_text(main_text)
        stale_one.write_text(
            "# one\nallow-hotplug eth2 mgt eth3\n"
            "iface mgt inet static\n address 192.0.2.3\n"
            "iface mgtbak inet manual\n bond-master mgt\n"
        )
        stale_two.write_text(
            "\n# two\nauto mgt\niface mgt inet static\n address 192.0.2.4\n"
            "iface other inet manual\n"
        )
        self.assertTrue(self.cli._apply_mgt_transaction(gateway="10.0.0.9"))
        combined = self.main.read_text() + stale_one.read_text() + stale_two.read_text()
        self.assertNotIn("address 192.0.2.", combined)
        for value in (
            "# main\n", "source /etc/network/interfaces.d/*.cfg\n", "iface lo inet loopback\n",
            "iface eth0 inet dhcp\n", "iface mgtpri inet manual\n",
            "iface mgtbak inet manual\n", "iface other inet manual\n", "# one\n", "# two\n",
        ):
            self.assertIn(value, combined)
        self.assertIn("auto lo eth0 # shared", self.main.read_text())
        self.assertIn("allow-hotplug eth1", self.main.read_text())
        self.assertIn("allow-hotplug eth2 eth3", stale_one.read_text())

    def test_40_mgt_callbacks_use_only_transaction_core(self):
        cases = (
            (self.cli.set_interface_callback, ("interface", ["mgt", "ip", "10.0.0.8/24"])),
            (self.cli.set_interface_callback, ("interface", ["mgt", "gateway", "10.0.0.9"])),
            (self.cli.set_interface_callback, (
                "interface",
                ["mgt", "ip", "10.0.0.8/24", "gateway", "10.0.0.9", "dns", "8.8.8.8"],
            )),
            (self.cli.set_dns_callback, ("dns", ["mgt", "9.9.9.9"])),
        )
        for callback, args in cases:
            self.cli._mgt_last_changed = True
            with mock.patch.object(self.cli, "_apply_mgt_transaction", return_value=True) as apply, \
                 mock.patch.object(self.cli, "set_interface_callback2") as callback2, \
                 mock.patch.object(self.cli, "update_interface_file") as generic, \
                 mock.patch.object(self.cli, "is_sensor_host_mode", return_value=True):
                callback(*args)
            apply.assert_called_once()
            callback2.assert_not_called()
            generic.assert_not_called()

    def test_41_single_ip_callback_never_creates_mgt_in_main(self):
        before_main = self.main.read_text()
        self.cli.set_interface_callback("interface", ["mgt", "ip", "10.7.0.2/24"])
        self.assertEqual(self.main.read_text(), before_main)
        self.assertIn("address 10.7.0.2", self.canonical.read_text())

    def test_42_commit_rollback_failure_reports_paths_and_cleans_temps(self):
        stale = self.directory / "99-old.cfg"
        stale.write_text("auto mgt\niface mgt inet static\n address 1.2.3.4\n")
        real_commit = module._commit_prepared_text_file
        real_atomic = module._atomic_replace_text_file

        def commit(path, temporary_path):
            if os.fspath(path) == str(self.canonical):
                raise module._AtomicCommitError(OSError("canonical failed"), replaced=False)
            return real_commit(path, temporary_path)

        def restore(path, text):
            if os.fspath(path) == str(stale):
                raise OSError("restore failed")
            return real_atomic(path, text)

        output = io.StringIO()
        with contextlib.redirect_stdout(output), \
             mock.patch.object(module, "_commit_prepared_text_file", side_effect=commit), \
             mock.patch.object(module, "_atomic_replace_text_file", side_effect=restore):
            self.assertFalse(self.cli._apply_mgt_transaction(gateway="10.0.0.9"))
        self.assertIn("Failed to update management configuration: canonical failed", output.getvalue())
        self.assertIn(
            "CRITICAL: Failed to restore management configuration: {}".format(stale),
            output.getvalue(),
        )
        self.assertFalse(any(path.name.startswith(".") for path in self.directory.iterdir()))

    def test_43_replaced_commit_failure_rolls_back_canonical(self):
        original = self.canonical.read_text()
        real_commit = module._commit_prepared_text_file

        def fail_after_replace(path, temporary_path):
            real_commit(path, temporary_path)
            raise module._AtomicCommitError(OSError("directory fsync failed"), replaced=True)

        with mock.patch.object(module, "_commit_prepared_text_file", side_effect=fail_after_replace):
            self.assertFalse(self.cli._apply_mgt_transaction(gateway="10.0.0.9"))
        self.assertEqual(self.canonical.read_text(), original)
        self.assertFalse(any(path.name.startswith(".") for path in self.directory.iterdir()))

    def test_44_restart_stderr_and_exact_argv(self):
        for failed_index, error in ((1, "ifdown stderr"), (2, "ifup stderr")):
            results = [mock.Mock(returncode=0, stdout="", stderr="") for _ in range(failed_index)]
            results.append(mock.Mock(returncode=1, stdout="", stderr=error))
            output = io.StringIO()
            with contextlib.redirect_stdout(output), \
                 mock.patch.object(module.subprocess, "run", side_effect=results) as run:
                self.assertFalse(self.cli._restart_mgt_interface())
            self.assertIn(error, output.getvalue())
            expected = [
                ["ifup", "--no-act", "mgt"],
                ["sudo", "ifdown", "--force", "mgt"],
                ["sudo", "ifup", "mgt"],
            ][:failed_index + 1]
            self.assertEqual([call.args[0] for call in run.call_args_list], expected)

    def test_45_restart_rejects_stale_runtime_address_and_gateway(self):
        without = BASE.replace("    address 10.0.0.2\n", "").replace(
            "    netmask 255.255.255.0\n", ""
        ).replace("    gateway 10.0.0.1\n", "")
        self.canonical.write_text(without)
        common = [mock.Mock(returncode=0, stdout="", stderr="") for _ in range(3)]
        with mock.patch.object(
            module.subprocess, "run",
            side_effect=common + [
                mock.Mock(returncode=0, stdout="inet 10.0.0.2/24", stderr=""),
                mock.Mock(returncode=0, stdout="", stderr=""),
            ],
        ):
            self.assertFalse(self.cli._restart_mgt_interface())
        with mock.patch.object(
            module.subprocess, "run",
            side_effect=common + [
                mock.Mock(returncode=0, stdout="", stderr=""),
                mock.Mock(returncode=0, stdout="default via 10.0.0.1 dev mgt", stderr=""),
            ],
        ):
            self.assertFalse(self.cli._restart_mgt_interface())
        with mock.patch.object(
            module.subprocess, "run",
            side_effect=common + [
                mock.Mock(returncode=0, stdout="", stderr=""),
                mock.Mock(returncode=0, stdout="", stderr=""),
            ],
        ):
            self.assertTrue(self.cli._restart_mgt_interface())

    def test_46_restart_verification_failure_rolls_back_transaction(self):
        before = self.canonical.read_text()
        results = [mock.Mock(returncode=0, stdout="", stderr="") for _ in range(3)] + [
            mock.Mock(returncode=0, stdout="inet 10.0.0.2/24", stderr=""),
            mock.Mock(returncode=0, stdout="default via 10.0.0.1 dev mgt", stderr=""),
        ]
        with mock.patch.object(module.subprocess, "run", side_effect=results):
            self.assertFalse(self.cli._apply_mgt_transaction(
                restart=True, address="10.0.0.8", netmask="24"
            ))
        self.assertEqual(self.canonical.read_text(), before)

    def test_47_show_gateway_uses_canonical_and_not_resolv_conf(self):
        real_open = open

        def guarded_open(path, *args, **kwargs):
            self.assertNotEqual(os.fspath(path), "/etc/resolv.conf")
            return real_open(path, *args, **kwargs)

        output = io.StringIO()
        with contextlib.redirect_stdout(output), \
             mock.patch("builtins.open", side_effect=guarded_open), \
             mock.patch.object(
                 module.subprocess, "run",
                 return_value=mock.Mock(returncode=0, stdout="", stderr=""),
             ):
            self.cli.show_gateway_callback("gateway", [])
        self.assertIn("Configured management gateway: 10.0.0.1", output.getvalue())

    def test_48_mgt_atomic_code_has_no_backup_implementation(self):
        sources = "\n".join(inspect.getsource(item) for item in (
            module._prepare_atomic_text_file,
            module._commit_prepared_text_file,
            module._atomic_replace_text_file,
            self.cli._apply_mgt_transaction,
            self.cli._restore_text_files,
        ))
        for forbidden in ("copy2", ".bak", ".orig", ".backup"):
            self.assertNotIn(forbidden, sources)

    def test_49_prepare_fchmod_and_fchown_failures_leave_no_temp(self):
        for patched, error in (
            ("fchmod", OSError("fchmod failed")),
            ("fchown", OSError("fchown failed")),
        ):
            with mock.patch.object(os, patched, side_effect=error):
                with self.assertRaisesRegex(OSError, str(error)):
                    module._prepare_atomic_text_file(self.canonical, "updated\n")
            self.assertEqual(
                sorted(path.name for path in self.directory.iterdir()),
                ["01-mgt.cfg"],
            )
            self.assertEqual(self.canonical.read_text(), BASE)

    def test_50_directory_fsync_failure_marks_commit_as_replaced(self):
        prepared = module._prepare_atomic_text_file(self.canonical, "updated\n")
        with mock.patch.object(os, "fsync", side_effect=OSError("directory fsync failed")):
            with self.assertRaises(module._AtomicCommitError) as raised:
                module._commit_prepared_text_file(self.canonical, prepared)
        self.assertTrue(raised.exception.replaced)
        self.assertEqual(self.canonical.read_text(), "updated\n")
        self.assertFalse(any(path.name.startswith(".") for path in self.directory.iterdir()))

    def test_51_second_commit_replace_failure_rolls_back_both_files(self):
        stale = self.directory / "99-old.cfg"
        stale_original = "auto mgt\niface mgt inet static\n address 1.2.3.4\n"
        stale.write_text(stale_original)
        canonical_original = self.canonical.read_text()
        real_commit = module._commit_prepared_text_file
        calls = {"count": 0}

        def fail_second_after_replace(path, temporary_path):
            calls["count"] += 1
            real_commit(path, temporary_path)
            if calls["count"] == 2:
                raise module._AtomicCommitError(
                    OSError("second commit fsync failed"), replaced=True
                )

        with mock.patch.object(
            module, "_commit_prepared_text_file", side_effect=fail_second_after_replace
        ):
            self.assertFalse(self.cli._apply_mgt_transaction(gateway="10.0.0.9"))
        self.assertEqual(stale.read_text(), stale_original)
        self.assertEqual(self.canonical.read_text(), canonical_original)
        self.assertFalse(any(path.name.startswith(".") for path in self.directory.iterdir()))

    def test_52_restart_rollback_failure_reports_critical_path(self):
        real_atomic = module._atomic_replace_text_file
        restart_called = {"value": False}

        def restart():
            restart_called["value"] = True
            return False

        def fail_restore(path, text):
            if restart_called["value"] and os.fspath(path) == str(self.canonical):
                raise OSError("restart rollback failed")
            return real_atomic(path, text)

        output = io.StringIO()
        with contextlib.redirect_stdout(output), \
             mock.patch.object(self.cli, "_restart_mgt_interface", side_effect=restart), \
             mock.patch.object(module, "_atomic_replace_text_file", side_effect=fail_restore):
            self.assertFalse(self.cli._apply_mgt_transaction(
                restart=True, gateway="10.0.0.9"
            ))
        self.assertIn(
            "CRITICAL: Failed to restore management configuration: {}".format(
                self.canonical
            ),
            output.getvalue(),
        )
        self.assertNotIn("success", output.getvalue().lower())

    def test_53_exact_dp_active_passive_fixture_is_preserved(self):
        topology = (
            "auto mgtpri\n"
            "iface mgtpri inet manual\n"
            "    bond-master mgt\n"
            "    bond-primary yes\n"
            "\n"
            "auto mgtbak\n"
            "iface mgtbak inet manual\n"
            "    bond-master mgt\n"
            "\n"
            "auto mgt\n"
            "iface mgt inet static\n"
            "    address 10.0.0.2\n"
            "    netmask 255.255.255.0\n"
            "    gateway 10.0.0.1\n"
            "    dns-nameservers 1.1.1.1\n"
            "\n"
            "    bond-slaves mgtpri mgtbak\n"
            "    bond-mode active-backup\n"
            "    bond-miimon 100\n"
            "    bond-updelay 200\n"
            "    bond-downdelay 200\n"
            "    bond-primary mgtpri\n"
            "    bond-primary-reselect always\n"
            "    x-unknown-option keep-this\n"
            "    # preserve this comment\n"
        )
        preserved = [
            line for line in topology.splitlines(keepends=True)
            if not re.match(
                r"^\s*(address|netmask|gateway|dns-nameservers)\s+", line
            )
        ]
        for args in (
            ["mgt", "ip", "10.0.1.2/24"],
            ["mgt", "gateway", "10.0.0.9"],
            ["mgt", "dns", "8.8.8.8", "8.8.4.4"],
        ):
            with open(self.canonical, "w", encoding="utf-8", newline="") as stream:
                stream.write(topology)
            self.cli.set_interface_callback("interface", args)
            with open(self.canonical, "r", encoding="utf-8", newline="") as stream:
                after = stream.read()
            actual = [
                line for line in after.splitlines(keepends=True)
                if not re.match(
                    r"^\s*(address|netmask|gateway|dns-nameservers)\s+", line
                )
            ]
            self.assertEqual(actual, preserved)

    def test_54_partial_rollback_reports_only_failed_path(self):
        stale = self.directory / "99-old.cfg"
        stale.write_text(
            "auto mgt\niface mgt inet static\n address 192.0.2.2\n"
        )
        real_commit = module._commit_prepared_text_file
        real_atomic = module._atomic_replace_text_file
        commit_count = {"value": 0}
        restore_order = []

        def fail_second_commit(path, temporary_path):
            commit_count["value"] += 1
            real_commit(path, temporary_path)
            if commit_count["value"] == 2:
                raise module._AtomicCommitError(
                    OSError("canonical directory fsync failed"), replaced=True
                )

        def partial_restore(path, text):
            restore_order.append(os.fspath(path))
            if os.fspath(path) == str(stale):
                raise OSError("stale restore failed")
            return real_atomic(path, text)

        output = io.StringIO()
        with contextlib.redirect_stdout(output), \
             mock.patch.object(
                 module, "_commit_prepared_text_file", side_effect=fail_second_commit
             ), \
             mock.patch.object(
                 module, "_atomic_replace_text_file", side_effect=partial_restore
             ):
            self.assertFalse(
                self.cli._apply_mgt_transaction(gateway="10.0.0.9")
            )
        self.assertEqual(restore_order, [str(self.canonical), str(stale)])
        self.assertIn(
            "CRITICAL: Failed to restore management configuration: {}".format(stale),
            output.getvalue(),
        )
        self.assertNotIn(str(self.canonical) + ",", output.getvalue())
        self.assertFalse(any(path.name.startswith(".") for path in self.directory.iterdir()))

    def test_55_changed_directive_preserves_own_indent_and_inline_comment(self):
        source = (
            "auto mgt\r\n"
            "iface mgt inet static\r\n"
            "\taddress 10.0.0.2  # address note\r\n"
            "  netmask 255.255.255.0 # mask note\r\n"
            "      gateway 10.0.0.1   # gateway note\r\n"
            " dns-nameservers 1.1.1.1 # dns note\r\n"
            "    bond-mode active-backup\r\n"
        )
        rendered = self.cli._render_mgt_ipv4_config(
            source,
            address="10.0.1.2",
            netmask="24",
            gateway="10.0.0.9",
            dns_nameservers=["8.8.8.8", "8.8.4.4"],
        )
        for expected in (
            "\taddress 10.0.1.2  # address note\r\n",
            "  netmask 255.255.255.0 # mask note\r\n",
            "      gateway 10.0.0.9   # gateway note\r\n",
            " dns-nameservers 8.8.8.8 8.8.4.4 # dns note\r\n",
            "    bond-mode active-backup\r\n",
        ):
            self.assertIn(expected, rendered)


if __name__ == "__main__":
    unittest.main()
