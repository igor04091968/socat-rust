#!/usr/bin/env python3
"""Opt-in control acceptance with synthetic loopback sessions and a restartable peer."""
import argparse
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
from test_tls_integration import Echo, Relay, exchange, rsa_pki, endpoints
from test_advice_integration import wait_for, rows

AUTO = "connect_timeout_seconds = 10\nadvice = { mode = 'auto', period_seconds = 1, min_samples = 1, stable_windows = 2, cooldown_windows = 2, max_step_seconds = 2 }"


class RestartableEcho(Echo):
    def __init__(self, port=0):
        self.socket = socket.socket()
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(('127.0.0.1', port))
        self.socket.listen(8)
        self.socket.settimeout(0.2)
        self.port = self.socket.getsockname()[1]
        self.stopped = threading.Event()
        self.accepted = 0
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()


def has_action(relay, action):
    return any('action=' + action + ' ' in row for row in rows(relay))


def run_auto(binary, tls=False, gost_fixture=None):
    checks = []
    with tempfile.TemporaryDirectory(prefix='socat-auto-test-') as tmp:
        root = Path(tmp)
        echo = RestartableEcho()
        relays = []
        held = None
        failed = None

        def relay(port, **kwargs):
            r = Relay(binary, root, port, **kwargs)
            relays.append(r)
            return r

        try:
            r = relay(echo.port, extra=AUTO)
            config_before = r.config.read_bytes()
            wait_for(r, lambda _: has_action(r, 'insufficient_data'))
            assert echo.accepted == 0
            checks.append('auto is passive without samples or probe traffic')
            held = socket.create_connection(('127.0.0.1', r.port), timeout=3)

            def heartbeat():
                held.sendall(b'keep')
                result = b''
                while len(result) < 4:
                    block = held.recv(4-len(result)); assert block
                    result += block
                assert result == b'keep'

            heartbeat()
            wait_for(r, lambda _: has_action(r, 'collect'))
            assert not has_action(r, 'apply')
            checks.append('waits for configured number of clean windows')
            exchange(r.port)
            wait_for(r, lambda _: has_action(r, 'apply'))
            assert any('action=apply ' in row and 'effective_timeout_seconds=8 ' in row and 'applied=true' in row for row in rows(r))
            heartbeat()
            checks.append('bounded change preserves the existing session')
            held.close(); held = None
            exchange(r.port)
            wait_for(r, lambda text: 'tcp_timeout_seconds=8 ' in text)
            checks.append('new upstream attempt actually uses adapted timeout')
            port = echo.port
            echo.close()
            failed = socket.create_connection(('127.0.0.1', r.port), timeout=3)
            wait_for(r, lambda _: has_action(r, 'rollback'))
            assert any('action=rollback ' in row and 'effective_timeout_seconds=10 ' in row for row in rows(r))
            checks.append('real upstream refusal rolls back to configured timeout')
            recover_offset = len(r.log.read_text())
            echo = RestartableEcho(port)
            exchange(r.port)
            wait_for(r, lambda text: 'tcp_timeout_seconds=10 ' in text[recover_offset:])
            wait_for(r, lambda _: has_action(r, 'cooldown'))
            assert r.config.read_bytes() == config_before
            checks.append('recovery uses baseline and cooldown without rewriting config')
            for key, value in [('stable_windows', 0), ('cooldown_windows', 0), ('max_step_seconds', 0)]:
                invalid = root/(key+'.toml')
                invalid.write_text(r.config.read_text().replace(key + ' = 2', key + ' = ' + str(value)))
                result = subprocess.run([str(binary), '--config', str(invalid), 'config-check'], capture_output=True, timeout=5)
                assert result.returncode != 0, key
            invalid = root/'initial-timeout.toml'
            invalid.write_text(r.config.read_text().replace('connect_timeout_seconds = 10', 'connect_timeout_seconds = 121'))
            assert subprocess.run([str(binary), '--config', str(invalid), 'config-check'], capture_output=True, timeout=5).returncode != 0
            checks.append('invalid controller limits and initial timeout are rejected')
            if tls:
                rsa = root/'rsa'; rsa.mkdir(); rsa_pki(rsa)
                inbound, outbound = endpoints(rsa)
                server = relay(echo.port, inbound=inbound)
                client = relay(server.port, outbound=outbound, extra=AUTO)
                exchange(client.port)
                wait_for(client, lambda _: has_action(client, 'collect'))
                exchange(client.port)
                wait_for(client, lambda _: has_action(client, 'apply'))
                exchange(client.port)
                checks.append('auto mode preserves mTLS verification and bidirectional exchange')
                bad = relay(server.port, outbound=dict(outbound, server_name='wrong.invalid'), extra=AUTO)
                try:
                    exchange(bad.port)
                except (OSError, AssertionError):
                    pass
                else:
                    raise AssertionError('bad certificate accepted in auto mode')
                wait_for(bad, lambda _: has_action(bad, 'degraded'))
                assert not has_action(bad, 'apply')
                checks.append('bad SAN fails closed; auto does not weaken TLS')
                if gost_fixture:
                    gost = root/'gost'; gost.mkdir()
                    subprocess.run([str(gost_fixture.resolve()), str(gost)], check=True, capture_output=True, timeout=30)
                    for cipher in ('kuznyechik', 'magma', 'gost28147', 'legacy28147'):
                        inbound, outbound = endpoints(gost, 'gost', cipher)
                        server = relay(echo.port, inbound=inbound)
                        client = relay(server.port, outbound=outbound, extra=AUTO)
                        exchange(client.port)
                        wait_for(client, lambda _: has_action(client, 'collect'))
                        exchange(client.port)
                        wait_for(client, lambda _: has_action(client, 'apply'))
                        exchange(client.port)
                        checks.append('auto preserves GOST mTLS ' + cipher)

        finally:
            if held is not None: held.close()
            if failed is not None: failed.close()
            for r in reversed(relays): r.close()
            echo.close()
    return checks


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--tls', action='store_true')
    parser.add_argument('--gost-fixture', type=Path)
    parser.add_argument('--results', type=Path, required=True)
    args = parser.parse_args()
    checks = run_auto(args.binary.resolve(), args.tls or bool(args.gost_fixture), args.gost_fixture)
    args.results.write_text(json.dumps({'passed': len(checks), 'checks': checks}, indent=2) + '\n')
    print('PASS', len(checks), 'automatic timeout acceptance checks', flush=True)


if __name__ == '__main__':
    main()
