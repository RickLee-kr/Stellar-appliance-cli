import logging.handlers
import contextlib
import io
import inspect
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

with mock.patch.object(logging.handlers.RotatingFileHandler, "__init__", return_value=None), \
     mock.patch.object(Path, "mkdir", return_value=None):
    import appliance_cli as module


CONF = (
    "# global\n"
    "server outside.example iburst\n"
    "# === XDR_NTPSEC_CONFIG_BEGIN ===\n"
    "# managed comment\n"
    "server one.example iburst\n"
    "pool two.example iburst\n"
    "restrict default kod\n"
    "\n"
    "# === XDR_NTPSEC_CONFIG_END ===\n"
    "tinker panic 0\n"
)


class NtpsecTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "ntp.conf"
        self.path.write_text(CONF, encoding="utf-8")
        self.cli = module.AellaCli.__new__(module.AellaCli)
        self.patch = mock.patch.object(module, "NTPSEC_CONFIG_PATH", str(self.path))
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.temp.cleanup()

    def test_01_constants(self):
        self.assertEqual(module.NTPSEC_SERVICE, "ntpsec")
        self.assertEqual(module.NTPSEC_QUERY_COMMAND, ["ntpq", "-pn"])

    def test_02_parse_decorated_markers(self):
        lines = CONF.splitlines(keepends=True)
        self.assertEqual(self.cli._parse_ntpsec_managed_block(lines), (2, 8))

    def test_03_parse_plain_markers(self):
        text = "# XDR_NTPSEC_CONFIG_BEGIN\nserver a iburst\n# XDR_NTPSEC_CONFIG_END\n"
        self.assertEqual(self.cli._parse_ntpsec_managed_block(text.splitlines(True)), (0, 2))

    def test_04_mismatched_marker_formats_fail(self):
        text = "# XDR_NTPSEC_CONFIG_BEGIN\n# === XDR_NTPSEC_CONFIG_END ===\n"
        with self.assertRaises(ValueError):
            self.cli._parse_ntpsec_managed_block(text.splitlines(True))

    def test_05_duplicate_markers_fail(self):
        text = (
            "# XDR_NTPSEC_CONFIG_BEGIN\n# XDR_NTPSEC_CONFIG_BEGIN\n"
            "# XDR_NTPSEC_CONFIG_END\n"
        )
        with self.assertRaises(ValueError):
            self.cli._parse_ntpsec_managed_block(text.splitlines(True))

    def test_06_add_unique_before_end(self):
        rendered, changed = self.cli._render_ntpsec_change(CONF, "add", ["three.example"])
        self.assertTrue(changed)
        self.assertIn("server three.example iburst\n# === XDR_NTPSEC_CONFIG_END ===", rendered)

    def test_07_add_duplicate_server_or_pool_is_noop(self):
        for target in ("one.example", "two.example"):
            rendered, changed = self.cli._render_ntpsec_change(CONF, "add", [target])
            self.assertFalse(changed)
            self.assertEqual(rendered, CONF)
        rendered, changed = self.cli._render_ntpsec_change(CONF, "add", ["outside.example"])
        self.assertTrue(changed)
        self.assertEqual(rendered.count("outside.example"), 2)

    def test_08_all_changes_fail_when_block_absent(self):
        source = "server outside.example iburst\n"
        for action in ("add", "replace", "unset"):
            with self.assertRaisesRegex(ValueError, "managed block not found"):
                self.cli._render_ntpsec_change(source, action, ["new.example"])

    def test_09_replace_deduplicates_in_order(self):
        rendered, changed = self.cli._render_ntpsec_change(
            CONF, "replace", ["b.example", "a.example", "b.example"]
        )
        self.assertTrue(changed)
        self.assertLess(rendered.index("server b.example"), rendered.index("server a.example"))
        self.assertEqual(rendered.count("server b.example"), 1)

    def test_10_replace_preserves_non_peer_content(self):
        rendered, _ = self.cli._render_ntpsec_change(CONF, "replace", ["new.example"])
        for value in ("# managed comment\n", "restrict default kod\n", "\n", "tinker panic 0\n"):
            self.assertIn(value, rendered)
        self.assertIn("server outside.example iburst", rendered)

    def test_11_unset_only_managed_peer(self):
        rendered, changed = self.cli._render_ntpsec_change(CONF, "unset", ["one.example"])
        self.assertTrue(changed)
        self.assertNotIn("server one.example", rendered)
        self.assertIn("server outside.example", rendered)

    def test_12_unset_outside_peer_is_noop(self):
        rendered, changed = self.cli._render_ntpsec_change(CONF, "unset", ["outside.example"])
        self.assertFalse(changed)
        self.assertEqual(rendered, CONF)

    def test_13_restart_failure_restores_and_restarts_again(self):
        updated = CONF.replace("one.example", "new.example")
        with mock.patch.object(self.cli, "_restart_ntp_service", side_effect=[False, True]) as restart:
            self.assertFalse(self.cli._commit_ntpsec_text(CONF, updated))
        self.assertEqual(self.path.read_text(encoding="utf-8"), CONF)
        self.assertEqual(restart.call_count, 2)

    def test_14_detect_requires_ntpsec_components(self):
        ok = mock.Mock(returncode=0, stdout="unit", stderr="")
        with mock.patch.object(module.subprocess, "run", return_value=ok), \
             mock.patch.object(module.shutil, "which", return_value="/usr/bin/ntpq"):
            self.assertEqual(
                self.cli._detect_ntp_type(),
                ("ntpsec", str(self.path), "ntpsec"),
            )

    def test_15_show_lists_only_managed_peers(self):
        runs = [
            mock.Mock(returncode=0, stdout="unit", stderr=""),
            mock.Mock(returncode=0, stdout="peer output", stderr=""),
            mock.Mock(returncode=0, stdout="active\n", stderr=""),
            mock.Mock(returncode=0, stdout="enabled\n", stderr=""),
            mock.Mock(returncode=0, stdout="peer output\n", stderr=""),
        ]
        with mock.patch.object(module.shutil, "which", return_value="/usr/bin/ntpq"), \
             mock.patch.object(module.subprocess, "run", side_effect=runs):
            status, output = self.cli.show_ntp_callback("ntp", [])
        self.assertEqual(status, 0)
        self.assertIn("server one.example", output)
        self.assertIn("pool two.example", output)
        self.assertNotIn("outside.example", output)

    def _callback_context(self, restart_side_effect=True, query_output=""):
        detect = mock.patch.object(
            self.cli, "_detect_ntp_type",
            return_value=("ntpsec", str(self.path), "ntpsec"),
        )
        restart = mock.patch.object(
            self.cli, "_restart_ntp_service", side_effect=restart_side_effect
            if isinstance(restart_side_effect, list) else None,
            return_value=restart_side_effect if not isinstance(restart_side_effect, list) else None,
        )
        query = mock.patch.object(
            module.subprocess, "run",
            return_value=mock.Mock(returncode=0, stdout=query_output, stderr=""),
        )
        return detect, restart, query

    def test_16_missing_ntpsec_has_no_fallback(self):
        self.path.unlink()
        output = io.StringIO()
        with contextlib.redirect_stdout(output), \
             mock.patch.object(module.subprocess, "run") as run:
            status = self.cli.set_ntp_callback("ntp", ["add", "new.example"])
        self.assertEqual(status, 1)
        run.assert_not_called()
        self.assertIn(
            "NTPsec is not installed or /etc/ntpsec/ntp.conf is missing.",
            output.getvalue(),
        )

    def test_17_set_add_callback_writes_atomically(self):
        detect, restart, query = self._callback_context()
        output = io.StringIO()
        with contextlib.redirect_stdout(output), detect, restart, query, \
             mock.patch.object(
                 module, "_atomic_replace_text_file",
                 wraps=module._atomic_replace_text_file,
             ) as writer:
            status = self.cli.set_ntp_callback("ntp", ["three.example"])
        self.assertEqual(status, 0)
        writer.assert_called_once()
        self.assertIn("server three.example iburst", self.path.read_text())
        self.assertEqual(
            sorted(path.name for path in Path(self.temp.name).iterdir()),
            ["ntp.conf"],
        )

    def test_18_replace_callback_preserves_non_peer_lines(self):
        detect, restart, query = self._callback_context()
        with detect, restart, query:
            status = self.cli.set_ntp_callback(
                "ntp", ["replace", "new1.example", "new2.example", "new1.example"]
            )
        self.assertEqual(status, 0)
        text = self.path.read_text()
        self.assertIn("# managed comment", text)
        self.assertIn("restrict default kod", text)
        self.assertIn("server outside.example", text)
        self.assertEqual(text.count("server new1.example"), 1)

    def test_19_unset_callback_only_removes_managed_peer(self):
        detect, restart, query = self._callback_context()
        with detect, restart, query:
            status = self.cli.unset_ntp_callback("ntp", ["server", "one.example"])
        self.assertEqual(status, 0)
        text = self.path.read_text()
        self.assertNotIn("server one.example", text)
        self.assertIn("server outside.example", text)

    def test_20_callback_restart_failure_rolls_back_without_success(self):
        detect, restart, query = self._callback_context([False, True])
        output = io.StringIO()
        before = self.path.read_text()
        with contextlib.redirect_stdout(output), detect, restart, query:
            status = self.cli.set_ntp_callback("ntp", ["failed.example"])
        self.assertEqual(status, 1)
        self.assertEqual(self.path.read_text(), before)
        self.assertNotIn("Successfully", output.getvalue())

    def test_21_second_restart_failure_is_reported(self):
        detect, restart, query = self._callback_context([False, False])
        output = io.StringIO()
        with contextlib.redirect_stdout(output), detect, restart, query:
            status = self.cli.set_ntp_callback("ntp", ["failed.example"])
        self.assertEqual(status, 1)
        self.assertIn(
            "NTPsec restart failed after restoring the original configuration.",
            output.getvalue(),
        )

    def test_22_reach_zero_warning_after_successful_write(self):
        ntpq = "*192.0.2.1 .GPS. 1 u 1 64 0 0.0 0.0 0.0\n"
        detect, restart, query = self._callback_context(True, ntpq)
        output = io.StringIO()
        with contextlib.redirect_stdout(output), detect, restart, query:
            status = self.cli.set_ntp_callback("ntp", ["reachzero.example"])
        self.assertEqual(status, 0)
        self.assertIn("Warning: NTP peers currently have reach=0", output.getvalue())

    def test_23_absent_block_callback_does_not_write_or_restart(self):
        self.path.write_text("server outside.example iburst\n")
        detect, restart, query = self._callback_context()
        output = io.StringIO()
        with contextlib.redirect_stdout(output), detect, restart as restart_mock, query, \
             mock.patch.object(module, "_atomic_replace_text_file") as writer:
            status = self.cli.set_ntp_callback("ntp", ["add", "new.example"])
        self.assertEqual(status, 1)
        writer.assert_not_called()
        restart_mock.assert_not_called()

    def test_24_ntp_code_has_single_callbacks_and_no_fallback(self):
        source = Path(module.__file__).read_text()
        self.assertEqual(source.count("    def set_ntp_callback("), 1)
        self.assertEqual(source.count("    def show_ntp_callback("), 1)
        self.assertEqual(source.count("    def unset_ntp_callback("), 1)
        ntp_section = source[
            source.index("    _NTPSEC_BLOCK_BEGIN_TAGS"):
            source.index("    def _get_local_interface_ips")
        ]
        for forbidden in ("timesyncd", "chrony", "legacy"):
            self.assertNotIn(forbidden, ntp_section.lower())
        self.assertNotIn("config updated", inspect.getsource(self.cli._restart_ntp_service).lower())

    def test_25_all_malformed_marker_shapes_leave_file_unchanged(self):
        malformed = (
            "# XDR_NTPSEC_CONFIG_BEGIN\nserver one.example iburst\n",
            "server one.example iburst\n# XDR_NTPSEC_CONFIG_END\n",
            "# XDR_NTPSEC_CONFIG_END\n# XDR_NTPSEC_CONFIG_BEGIN\n",
            (
                "# XDR_NTPSEC_CONFIG_BEGIN\nserver one.example iburst\n"
                "# XDR_NTPSEC_CONFIG_END\n# XDR_NTPSEC_CONFIG_BEGIN\n"
                "server two.example iburst\n# XDR_NTPSEC_CONFIG_END\n"
            ),
        )
        for text in malformed:
            self.path.write_text(text)
            detect, restart, query = self._callback_context()
            with detect, restart as restart_mock, query, \
                 mock.patch.object(module, "_atomic_replace_text_file") as writer:
                self.assertEqual(
                    self.cli.set_ntp_callback("ntp", ["add", "new.example"]), 1
                )
            self.assertEqual(self.path.read_text(), text)
            restart_mock.assert_not_called()
            writer.assert_not_called()

    def test_26_add_and_unset_preserve_complete_peer_lines_exactly(self):
        source = (
            "server outside.example minpoll 4\n"
            "# === XDR_NTPSEC_CONFIG_BEGIN ===\n"
            "# comment\n"
            "server time1.google.com prefer minpoll 6 maxpoll 10\n"
            "pool pool.example iburst minpoll 5 maxpoll 9\n"
            "tinker panic 0\nrestrict default kod\n\nunknown value\n"
            "# === XDR_NTPSEC_CONFIG_END ===\n"
            "restrict outside nomodify\n"
        )
        added, changed = self.cli._render_ntpsec_change(
            source, "add", ["new.example"]
        )
        self.assertTrue(changed)
        for exact in (
            "server time1.google.com prefer minpoll 6 maxpoll 10\n",
            "pool pool.example iburst minpoll 5 maxpoll 9\n",
            "tinker panic 0\n", "restrict default kod\n",
            "unknown value\n", "restrict outside nomodify\n",
        ):
            self.assertEqual(added.count(exact), source.count(exact))
        unset, changed = self.cli._render_ntpsec_change(
            added, "unset", ["time1.google.com"]
        )
        self.assertTrue(changed)
        self.assertNotIn("server time1.google.com", unset)
        self.assertIn("pool pool.example iburst minpoll 5 maxpoll 9\n", unset)
        self.assertIn("server outside.example minpoll 4\n", unset)

    def test_27_replace_removes_peer_options_only(self):
        source = CONF.replace(
            "server one.example iburst\n",
            "server one.example prefer iburst minpoll 6 maxpoll 10\n",
        ).replace(
            "pool two.example iburst\n",
            "pool two.example iburst minpoll 5 maxpoll 9\n",
        )
        rendered, changed = self.cli._render_ntpsec_change(
            source, "replace", ["new.example"]
        )
        self.assertTrue(changed)
        self.assertIn("server new.example iburst\n", rendered)
        self.assertNotIn("prefer", rendered)
        self.assertNotIn("minpoll", rendered)
        for exact in (
            "# managed comment\n", "restrict default kod\n",
            "server outside.example iburst\n", "tinker panic 0\n",
        ):
            self.assertEqual(rendered.count(exact), source.count(exact))

    def test_28_unset_normalizes_and_validates_target(self):
        detect, restart, query = self._callback_context()
        with detect, restart, query:
            self.assertEqual(
                self.cli.unset_ntp_callback("ntp", ["server", "one.example"]), 0
            )
        self.assertNotIn("server one.example", self.path.read_text())

        for target in ("", "999.999.999.999", "bad host", "$(touch /tmp/pwned)"):
            output = io.StringIO()
            params = [target] if target else []
            with contextlib.redirect_stdout(output), \
                 mock.patch.object(self.cli, "_ntpsec_operation") as operation, \
                 mock.patch.object(module.subprocess, "run") as run:
                result = self.cli.unset_ntp_callback("ntp", params)
            operation.assert_not_called()
            run.assert_not_called()
            self.assertNotEqual(result, 0)
        self.assertFalse(self.cli.is_valid_hostname(""))
        self.assertTrue(self.cli._is_valid_ntp_target("192.0.2.1"))
        self.assertTrue(self.cli._is_valid_ntp_target("time.example.com"))

    def test_29_rollback_atomic_failure_is_critical_without_success(self):
        updated = CONF.replace("one.example", "new.example")
        output = io.StringIO()
        with contextlib.redirect_stdout(output), \
             mock.patch.object(
                 module, "_atomic_replace_text_file",
                 side_effect=[None, OSError("rollback write failed")],
             ), \
             mock.patch.object(self.cli, "_restart_ntp_service", return_value=False):
            self.assertFalse(self.cli._commit_ntpsec_text(CONF, updated))
        self.assertIn(
            "CRITICAL: Failed to restore NTP configuration: rollback write failed "
            "Manual recovery is required.",
            output.getvalue(),
        )
        self.assertNotIn("Successfully", output.getvalue())

    def test_30_second_restart_failure_has_manual_systemctl_guidance(self):
        updated = CONF.replace("one.example", "new.example")
        output = io.StringIO()
        with contextlib.redirect_stdout(output), \
             mock.patch.object(self.cli, "_restart_ntp_service", side_effect=[False, False]):
            self.assertFalse(self.cli._commit_ntpsec_text(CONF, updated))
        self.assertIn(
            "Run 'sudo -n systemctl restart ntpsec' manually.",
            output.getvalue(),
        )
        self.assertNotIn("Successfully", output.getvalue())

    def test_31_initial_atomic_failure_does_not_restart_or_leave_temp(self):
        updated = CONF.replace("one.example", "new.example")
        with mock.patch.object(
            module, "_atomic_replace_text_file", side_effect=OSError("initial write failed")
        ), mock.patch.object(self.cli, "_restart_ntp_service") as restart:
            self.assertFalse(self.cli._commit_ntpsec_text(CONF, updated))
        restart.assert_not_called()
        self.assertEqual(
            sorted(path.name for path in Path(self.temp.name).iterdir()),
            ["ntp.conf"],
        )

    def test_32_callback_uses_only_fixed_subprocess_argv(self):
        calls = []

        def run(argv, **kwargs):
            calls.append(argv)
            if argv == ["systemctl", "cat", "ntpsec"]:
                return mock.Mock(returncode=0, stdout="unit", stderr="")
            if argv == ["ntpq", "-pn"]:
                return mock.Mock(returncode=0, stdout="", stderr="")
            if argv == ["sudo", "-n", "systemctl", "restart", "ntpsec"]:
                return mock.Mock(returncode=0, stdout="", stderr="")
            raise AssertionError("unexpected argv: {!r}".format(argv))

        with mock.patch.object(module.shutil, "which", return_value="/usr/bin/ntpq"), \
             mock.patch.object(module.subprocess, "run", side_effect=run):
            self.assertEqual(
                self.cli.set_ntp_callback("ntp", ["add", "192.0.2.10"]), 0
            )
        self.assertEqual(calls, [
            ["systemctl", "cat", "ntpsec"],
            ["ntpq", "-pn"],
            ["sudo", "-n", "systemctl", "restart", "ntpsec"],
            ["ntpq", "-pn"],
        ])
        self.assertIn("server 192.0.2.10 iburst", self.path.read_text())

    def test_33_first_restart_failure_restores_then_restarts_fixed_argv(self):
        updated = CONF.replace("one.example", "new.example")
        results = [
            mock.Mock(returncode=1, stdout="", stderr="first"),
            mock.Mock(returncode=0, stdout="", stderr=""),
        ]
        with mock.patch.object(module.subprocess, "run", side_effect=results) as run:
            self.assertFalse(self.cli._commit_ntpsec_text(CONF, updated))
        self.assertEqual([call.args[0] for call in run.call_args_list], [
            ["sudo", "-n", "systemctl", "restart", "ntpsec"],
            ["sudo", "-n", "systemctl", "restart", "ntpsec"],
        ])
        self.assertEqual(self.path.read_text(), CONF)

    def test_34_ntp_atomic_code_has_no_backup_or_copy(self):
        source = "\n".join(inspect.getsource(item) for item in (
            module._prepare_atomic_text_file,
            module._commit_prepared_text_file,
            module._atomic_replace_text_file,
            self.cli._commit_ntpsec_text,
        ))
        for forbidden in ("copy2", ".bak", ".orig", ".backup"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
