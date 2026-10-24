#!/usr/bin/env python3
"""Offline tests: no real systemctl, binary, credentials or network."""
import contextlib
import fcntl
import importlib.machinery
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

source = os.environ.get("SOCAT_MANAGER_SOURCE", str(Path(__file__).with_name("socat-connectors")))
loader = importlib.machinery.SourceFileLoader("manager", source)
spec = importlib.util.spec_from_loader(loader.name, loader)
manager = importlib.util.module_from_spec(spec)
loader.exec_module(manager)


class ManagerTests(unittest.TestCase):
    def test_scope_padding_and_missing(self):
        data = {"relay": [{"name": name} for name in
                ("bnk2450038", "bnk2450037", "bnk2450001", "bnk2450006")]}
        self.assertEqual([r["name"] for r in manager.select_relays(data)],
                         ["bnk2450001", "bnk2450006", "bnk2450037"])

    def test_reject_bad_selection(self):
        for data, requested in [
                ({"relay": []}, None),
                ({"relay": [{"name": "bnk2450001"}] * 2}, None),
                ({"relay": [{"name": "bnk2450038"}]}, "bnk2450038"),
                ({"relay": [{"name": "bnk2450001"}]}, "../../sshd")]:
            with self.subTest(data=data, requested=requested), self.assertRaises(ValueError):
                manager.select_relays(data, requested)

    def test_status_reports_partial_failure(self):
        good = "Id=socat-rust@bnk2450001.service\nActiveState=active\nSubState=running\nMainPID=321\nNRestarts=0\nUnitFileState=enabled"
        bad = "Id=socat-rust@bnk2450011.service\nActiveState=activating\nSubState=auto-restart\nMainPID=0\nNRestarts=1\nUnitFileState=disabled"
        with patch.object(manager, "run", return_value=good + "\n\n" + bad), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(manager.status(["one", "eleven"]), 1)
        self.assertIn("bnk2450001", output.getvalue())
        self.assertIn("bnk2450011", output.getvalue())
        with patch.object(manager, "run", return_value=good), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(manager.status(["one"]), 0)

    def test_error_and_timeout_not_success(self):
        result = subprocess.CompletedProcess(["fake"], 1, "", "bind failed")
        with patch.object(manager.subprocess, "run", return_value=result), self.assertRaisesRegex(RuntimeError, "bind failed"):
            manager.run(["fake"])
        with patch.object(manager.subprocess, "run", side_effect=subprocess.TimeoutExpired("fake", 1)), self.assertRaises(subprocess.TimeoutExpired):
            manager.run(["fake"], timeout=1)

    def test_invalid_config_prevents_start(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(manager.os, "geteuid", return_value=0), patch.object(manager, "LOCK", Path(directory) / "lock"), patch.object(manager, "run", side_effect=RuntimeError("invalid TOML")) as call, self.assertRaises(RuntimeError):
            manager.control("start", [{"name": "bnk2450001"}])
        self.assertEqual(call.call_count, 1)
        self.assertEqual(call.call_args.args[0][-1], "config-check")

    def test_parallel_mutation_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock"
            with path.open("a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with patch.object(manager, "LOCK", path), patch.object(manager.os, "geteuid", return_value=0), patch.object(manager, "run") as call:
                    with self.assertRaisesRegex(RuntimeError, "ещё выполняется"):
                        manager.control("stop", [{"name": "bnk2450001"}])
                    call.assert_not_called()

    def test_start_uses_foreground_units_without_enabling(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(manager, "LOCK", Path(directory) / "lock"), patch.object(manager.os, "geteuid", return_value=0), patch.object(manager, "run", return_value="") as call, patch.object(manager, "status", return_value=0), patch.object(manager, "manual_process", return_value=None), patch.object(manager, "ready_relays", side_effect=lambda relays: (relays, [])), patch.object(manager.time, "sleep"), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(manager.control("start", [{"name": "bnk2450001"}]), 0)
            commands = [c.args[0] for c in call.call_args_list]
            self.assertEqual(len(commands), 3)
            self.assertEqual(commands[1][1], "list-units")
            self.assertEqual(commands[2][1], "start")
            self.assertIn("socat-rust@bnk2450001.service", commands[2])
            self.assertNotIn("--daemon", str(commands))
            self.assertNotIn("enable", str(commands))

    def test_manual_daemon_identity_and_stale_pid(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            lockfile = base / "relay.lock"
            relay = {"name": "bnk2450001", "uid": 4321, "pid_file": str(lockfile)}
            proc = base / "12345"
            (proc / "fd").mkdir(parents=True)
            (proc / "fdinfo").mkdir()
            (proc / "exe").symlink_to(manager.sys.executable)
            (proc / "status").write_text("Uid:\t4321\t4321\t4321\t4321\n")
            args = [manager.sys.executable, "--config", str(manager.CONFIG), "--relay", relay["name"], "--daemon"]
            (proc / "cmdline").write_bytes(b"\0".join(a.encode() for a in args) + b"\0")
            (proc / "fd" / "3").symlink_to(lockfile)
            (proc / "fdinfo" / "3").write_text("lock: 1: FLOCK ADVISORY WRITE 12344 00:18:1 0 EOF\n")
            lockfile.write_text("12345\n")
            with lockfile.open("r+") as held:
                fcntl.flock(held, fcntl.LOCK_EX)
                with patch.object(manager, "PROC", base), patch.object(manager, "BINARY", manager.sys.executable), patch.object(manager.os, "pidfd_open", side_effect=lambda pid: os.open("/dev/null", os.O_RDONLY)):
                    found = manager.manual_process(relay)
                    self.assertEqual(found[0], 12345)
                    os.close(found[1])
                    (proc / "cmdline").write_bytes(b"/usr/bin/other\0")
                    self.assertIsNone(manager.manual_process(relay))
                    (proc / "cmdline").write_bytes(b"\0".join(a.encode() for a in args) + b"\0")
                    (proc / "status").write_text("Uid:\t999\t999\t999\t999\n")
                    self.assertIsNone(manager.manual_process(relay))
            with patch.object(manager, "PROC", base), patch.object(manager.os, "pidfd_open") as opened:
                self.assertIsNone(manager.manual_process(relay))
                opened.assert_not_called()

    def test_missing_ip_is_not_started(self):
        relays = [{"name": "bnk2450001", "listen": "0.0.0.0:8001"},
                  {"name": "bnk2450011", "listen": "10.34.0.1:8011"}]
        with patch.object(manager, "run", return_value="[]"), contextlib.redirect_stderr(io.StringIO()) as message:
            ready, missing = manager.ready_relays(relays)
        self.assertEqual(ready, [relays[0]])
        self.assertEqual(missing, [relays[1]])
        self.assertIn("10.34.0.1", message.getvalue())

    def test_start_refuses_manual_daemon(self):
        with tempfile.TemporaryDirectory() as directory:
            descriptor = os.open("/dev/null", os.O_RDONLY)
            with patch.object(manager.os, "geteuid", return_value=0), patch.object(manager, "LOCK", Path(directory) / "lock"), patch.object(manager, "run", return_value="") as call, patch.object(manager, "manual_process", return_value=(12345, descriptor)):
                with self.assertRaisesRegex(RuntimeError, "ручной процесс"):
                    manager.control("start", [{"name": "bnk2450001"}])
                self.assertEqual(call.call_count, 1)
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_stop_manual_uses_pidfd_only(self):
        read_fd, write_fd = os.pipe()
        os.close(write_fd)
        with patch.object(manager, "manual_process", return_value=(12345, read_fd)), patch.object(manager.signal, "pidfd_send_signal") as sent, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(manager.stop_manual([{"name": "bnk2450001"}]), 1)
        sent.assert_called_once_with(read_fd, manager.signal.SIGTERM)
        with self.assertRaises(OSError):
            os.fstat(read_fd)

    def test_restart_stops_manual_before_systemd_start(self):
        events = []
        with tempfile.TemporaryDirectory() as directory, patch.object(manager.os, "geteuid", return_value=0), patch.object(manager, "LOCK", Path(directory) / "lock"), patch.object(manager, "run", side_effect=lambda cmd, **kw: events.append(cmd[1]) or ""), patch.object(manager, "stop_manual", side_effect=lambda relays: events.append("stop_manual") or 1), patch.object(manager, "ready_relays", side_effect=lambda relays: (relays, [])), patch.object(manager, "status", return_value=0), patch.object(manager.time, "sleep"), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(manager.control("restart", [{"name": "bnk2450001"}]), 0)
        self.assertLess(events.index("stop"), events.index("stop_manual"))
        self.assertLess(events.index("stop_manual"), events.index("start"))

    def test_status_exposes_manual_process(self):
        record = "Id=socat-rust@bnk2450001.service\nActiveState=activating\nSubState=auto-restart\nMainPID=0\nNRestarts=3\nUnitFileState=disabled"
        descriptor = os.open("/dev/null", os.O_RDONLY)
        with patch.object(manager, "run", return_value=record), patch.object(manager, "manual_process", return_value=(12345, descriptor)), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(manager.status(["unit"], [{"name": "bnk2450001"}]), 1)
        self.assertIn("manual/running", output.getvalue())
        self.assertIn("12345", output.getvalue())

    def test_only_loaded_failed_units_are_reset(self):
        unit = "socat-rust@bnk2450001.service"
        calls = []
        def fake_run(command, **kwargs):
            calls.append(command)
            return unit + " loaded failed failed description\n" if command[1] == "list-units" else ""
        with tempfile.TemporaryDirectory() as directory, patch.object(manager.os, "geteuid", return_value=0), patch.object(manager, "LOCK", Path(directory) / "lock"), patch.object(manager, "run", side_effect=fake_run), patch.object(manager, "manual_process", return_value=None), patch.object(manager, "ready_relays", side_effect=lambda relays: (relays, [])), patch.object(manager, "status", return_value=0), patch.object(manager.time, "sleep"), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(manager.control("start", [{"name": "bnk2450001"}, {"name": "bnk2450002"}]), 0)
        reset = [c for c in calls if c[1] == "reset-failed"]
        self.assertEqual(reset, [[manager.SYSTEMCTL, "reset-failed", unit]])


if __name__ == "__main__":
    unittest.main()
