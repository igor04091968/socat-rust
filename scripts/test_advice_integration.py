#!/usr/bin/env python3
"""Passive advice acceptance. Synthetic loopback traffic, no production endpoints."""
import argparse
import json
from pathlib import Path
import re
import socket
import tempfile
import time
from test_tls_integration import Echo, Relay, endpoints, exchange, rsa_pki, unused_port

ADVICE = "advice = { mode = 'recommend', period_seconds = 1, min_samples = 1 }"


def wait_for(relay, predicate, seconds=5):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        text = relay.log.read_text()
        if predicate(text):
            return text
        assert relay.process.poll() is None, text
        time.sleep(0.05)
    raise AssertionError(relay.log.read_text())


def rows(relay):
    return [line for line in relay.log.read_text().splitlines() if 'connection_advice:' in line]


def total(relay, field):
    return sum(int(re.search(r'\b' + field + r'=(\d+)', row).group(1)) for row in rows(relay))


def exercise(binary, tls=False):
    checks = []
    with tempfile.TemporaryDirectory(prefix='socat-advice-test-') as tmp:
        root = Path(tmp)
        echo = Echo(root)
        relays = []

        def relay(port, **kwargs):
            r = Relay(binary, root, port, **kwargs)
            relays.append(r)
            return r

        try:
            quiet = relay(echo.port, extra=ADVICE)
            wait_for(quiet, lambda t: 'connection_advice:' in t)
            assert echo.accepted == 0, 'passive observer made an upstream probe'
            assert 'suggested_timeout_seconds=None' in rows(quiet)[0]
            checks.append('idle window, insufficient samples, no active probes')
            for _ in range(3):
                exchange(quiet.port)
            wait_for(quiet, lambda _: total(quiet, 'tcp_ok') == 3)
            assert any('suggested_timeout_seconds=Some(3)' in r and 'applied=false' in r for r in rows(quiet))
            checks.append('successful TCP samples and bounded recommendation')
            held = [socket.create_connection(('127.0.0.1', quiet.port), timeout=3) for _ in range(4)]
            try:
                wait_for(quiet, lambda _: total(quiet, 'tcp_ok') == 7)
                count = len(rows(quiet))

                def sessions_alive(_):
                    for sock in held:
                        sock.sendall(b'after report')
                        received = b''
                        while len(received) < 12:
                            block = sock.recv(12 - len(received))
                            assert block, 'active session closed by report'
                            received += block
                        assert received == b'after report'
                    return len(rows(quiet)) > count

                wait_for(quiet, sessions_alive)
                checks.append('periodic report at full capacity preserves active sessions')
            finally:
                for sock in held:
                    sock.close()
            disabled = relay(echo.port)
            exchange(disabled.port)
            time.sleep(1.15)
            assert not rows(disabled)
            checks.append('default off preserves exchange without advice logs')
            failed = relay(unused_port(), extra=ADVICE)
            with socket.create_connection(('127.0.0.1', failed.port), timeout=3):
                wait_for(failed, lambda _: total(failed, 'tcp_errors') >= 1)
            assert any('degraded=true' in r and 'suggested_timeout_seconds=None' in r for r in rows(failed))
            checks.append('refused TCP recorded as failure without false latency')
            if tls:
                rsa = root/'rsa'; rsa.mkdir(); rsa_pki(rsa)
                inbound, outbound = endpoints(rsa)
                server = relay(echo.port, inbound=inbound)
                client = relay(server.port, outbound=outbound, extra=ADVICE)
                exchange(client.port)
                wait_for(client, lambda _: total(client, 'tls_ok') == 1)
                assert total(client, 'tcp_ok') == 1
                checks.append('mTLS handshake measured separately from TCP')
                bad = relay(server.port, outbound=dict(outbound, server_name='wrong.invalid'), extra=ADVICE)
                try:
                    exchange(bad.port)
                except (OSError, AssertionError):
                    pass
                else:
                    raise AssertionError('bad TLS identity accepted')
                wait_for(bad, lambda _: total(bad, 'tls_errors') == 1)
                assert total(bad, 'tcp_ok') == 1
                assert any('degraded=true' in r and 'suggested_timeout_seconds=None' in r for r in rows(bad))
                checks.append('wrong SAN remains fail closed and suppresses recommendation')
        finally:
            for r in reversed(relays):
                r.close()
            echo.close()
    return checks


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--tls', action='store_true')
    parser.add_argument('--results', type=Path, required=True)
    args = parser.parse_args()
    checks = exercise(args.binary.resolve(), args.tls)
    args.results.write_text(json.dumps({'passed': len(checks), 'checks': checks}, indent=2) + '\n')
    print('PASS', len(checks), 'passive advice acceptance checks')


if __name__ == '__main__':
    main()
