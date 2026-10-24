#!/usr/bin/env python3
"""Bounded localhost integration tests. All certificates and payloads are synthetic."""
import argparse
import contextlib
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time


def command(args, **kwargs):
    return subprocess.run([str(x) for x in args], check=True, capture_output=True, timeout=15, **kwargs)


def unused_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class Echo:
    def __init__(self, directory):
        self.socket = socket.socket()
        self.socket.bind(('127.0.0.1', 0))
        self.socket.listen(8)
        self.socket.settimeout(0.2)
        self.port = self.socket.getsockname()[1]
        self.stopped = threading.Event()
        self.accepted = 0
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stopped.is_set():
            try:
                conn, _ = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.accepted += 1
            threading.Thread(target=self.connection, args=(conn,), daemon=True).start()

    def connection(self, conn):
        with conn:
            conn.settimeout(3)
            try:
                while data := conn.recv(65536):
                    conn.sendall(data)
            except OSError:
                pass

    def close(self):
        self.stopped.set()
        self.socket.close()
        self.thread.join(1)


class Relay:
    def __init__(self, binary, directory, upstream, inbound=None, outbound=None, extra=''):
        self.port = unused_port()
        name = 'relay-' + str(self.port)
        self.config = directory / (name + '.toml')
        self.log = directory / (name + '.log')
        text = f'''[[relay]]
name = "{name}"
listen = "127.0.0.1:{self.port}"
upstream = "127.0.0.1:{upstream}"
pid_file = "{directory / (name + '.lock')}"
max_connections = 4
eof_grace_seconds = 1
{extra}
'''
        for section, values in [('inbound_tls', inbound), ('outbound_tls', outbound)]:
            if values:
                text += f'\n[relay.{section}]\n'
                for key, value in values.items():
                    text += key + ' = ' + json.dumps(str(value) if isinstance(value, Path) else value) + '\n'
        self.config.write_text(text)
        self.output = self.log.open('w')
        self.process = subprocess.Popen([str(binary), '--config', str(self.config), '--relay', name],
                                        stdout=self.output, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.close()
                raise AssertionError(self.log.read_text())
            if 'relay слушает входящий порт' in self.log.read_text():
                return
            time.sleep(0.04)
        self.close()
        raise AssertionError('listener did not start: ' + self.log.read_text())

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(3)
        self.output.close()


def exchange(port, tls_context=None, identity='localhost'):
    payload = b'local TLS synthetic test\x00\xff' * 64
    with socket.create_connection(('127.0.0.1', port), timeout=4) as sock:
        stream = tls_context.wrap_socket(sock, server_hostname=identity) if tls_context else sock
        with stream:
            stream.sendall(payload)
            result = b''
            while len(result) < len(payload):
                block = stream.recv(len(payload) - len(result))
                if not block:
                    break
                result += block
            assert result == payload, (len(result), len(payload))
    return True


def rsa_pki(directory):
    command(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
             '-subj', '/CN=Synthetic TLS CA', '-keyout', directory/'ca.key', '-out', directory/'ca.pem'])
    extension = directory/'leaf.ext'
    extension.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n')
    for name in ('server', 'client'):
        command(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN='+name,
                 '-keyout', directory/(name+'.key'), '-out', directory/(name+'.csr')])
        command(['openssl', 'x509', '-req', '-in', directory/(name+'.csr'), '-CA', directory/'ca.pem',
                 '-CAkey', directory/'ca.key', '-CAcreateserial', '-days', '2', '-extfile', extension,
                 '-out', directory/(name+'.pem')])


def endpoints(directory, mode='tls', cipher=None, client=True):
    inbound = dict(mode=mode, certificate=directory/'server.pem', private_key=directory/'server.key',
                   client_ca=directory/'ca.pem', handshake_timeout_seconds=2)
    outbound = dict(mode=mode, ca_file=directory/'ca.pem', server_name='localhost', handshake_timeout_seconds=2)
    if client:
        outbound.update(certificate=directory/'client.pem', private_key=directory/'client.key')
    if cipher:
        inbound['gost_cipher'] = outbound['gost_cipher'] = cipher
    return inbound, outbound


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--plain-binary', type=Path)
    parser.add_argument('--gost-fixture', type=Path)
    parser.add_argument('--results', type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve()
    results = []
    with tempfile.TemporaryDirectory(prefix='socat-tls-tests-') as tmp:
        root = Path(tmp)
        rsa = root/'rsa'; rsa.mkdir(); rsa_pki(rsa)
        other = root/'other'; other.mkdir(); rsa_pki(other)
        echo = Echo(root)
        relays = []
        def relay(*a, **kw):
            result = Relay(binary, root, *a, **kw)
            relays.append(result)
            return result
        def check(label, operation):
            operation()
            results.append(label)
            print('PASS', label, flush=True)
        def denied(port, context=None, identity='localhost'):
            try:
                exchange(port, context, identity)
            except (OSError, ssl.SSLError, AssertionError):
                return
            raise AssertionError('connection unexpectedly succeeded')
        try:
            plain = relay(echo.port)
            check('plain TCP preserved in TLS binary', lambda: exchange(plain.port))
            inbound, outbound = endpoints(rsa)
            server = relay(echo.port, inbound=inbound)
            ctx = ssl.create_default_context(cafile=str(rsa/'ca.pem'))
            ctx.load_cert_chain(rsa/'client.pem', rsa/'client.key')
            check('independent Python TLS client to mTLS relay', lambda: exchange(server.port, ctx))
            for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
                versioned = ssl.create_default_context(cafile=str(rsa/'ca.pem'))
                versioned.minimum_version = versioned.maximum_version = version
                versioned.load_cert_chain(rsa/'client.pem', rsa/'client.key')
                check('independent '+version.name+' handshake', lambda: exchange(server.port, versioned))
            client = relay(server.port, outbound=outbound)
            check('TLS client/server mTLS bidirectional payload', lambda: exchange(client.port))
            ip_client = relay(server.port, outbound=dict(outbound, server_name='127.0.0.1'))
            check('outbound IP SAN verified', lambda: exchange(ip_client.port))
            bridge = relay(server.port, inbound=inbound, outbound=outbound)
            check('TLS on both legs', lambda: exchange(bridge.port, ctx))
            before = echo.accepted
            no_cert = ssl.create_default_context(cafile=str(rsa/'ca.pem'))
            check('mTLS rejects missing client certificate', lambda: denied(server.port, no_cert))
            time.sleep(0.1)
            assert echo.accepted == before, 'unauthenticated inbound reached upstream'
            check('mTLS rejects plain TCP without upstream connection', lambda: denied(server.port))
            wrong = dict(outbound, server_name='wrong.invalid')
            wrong_client = relay(server.port, outbound=wrong)
            check('outbound wrong DNS SAN fails closed', lambda: denied(wrong_client.port))
            wrong_ca = relay(server.port, outbound=dict(outbound, ca_file=other/'ca.pem'))
            check('outbound unrelated CA fails closed', lambda: denied(wrong_ca.port))
            impostor = ssl.create_default_context(cafile=str(rsa/'ca.pem'))
            impostor.load_cert_chain(other/'client.pem', other/'client.key')
            check('mTLS rejects untrusted client identity', lambda: denied(server.port, impostor))
            # Validate the configured timeout instead of leaving a slot occupied indefinitely.
            with socket.create_connection(('127.0.0.1', server.port), timeout=3) as stall:
                stall.settimeout(4)
                start = time.monotonic()
                assert stall.recv(1) == b''
                assert 1.5 <= time.monotonic() - start < 4
            results.append('inbound handshake timeout releases connection')
            if args.plain_binary:
                check_result = subprocess.run([str(args.plain_binary.resolve()), '--config', str(server.config), 'config-check'], capture_output=True, timeout=5)
                assert check_result.returncode != 0 and b'without feature tls' in check_result.stderr
                results.append('non-TLS binary rejects TLS profile')
            if args.gost_fixture:
                gost = root/'gost'; gost.mkdir()
                command([args.gost_fixture.resolve(), gost])
                for cipher in ('kuznyechik', 'magma', 'gost28147', 'legacy28147'):
                    inbound, outbound = endpoints(gost, 'gost', cipher)
                    gs = relay(echo.port, inbound=inbound)
                    gc = relay(gs.port, outbound=outbound)
                    check('GOST TLS1.2 '+cipher+' mTLS', lambda: exchange(gc.port))
                    names = {'kuznyechik': 'GOST2012-KUZNYECHIK-KUZNYECHIKOMAC', 'magma': 'GOST2012-MAGMA-MAGMAOMAC', 'gost28147': 'IANA-GOST2012-GOST8912-GOST8912', 'legacy28147': 'LEGACY-GOST2012-GOST8912-GOST8912'}
                    assert names[cipher] in gs.log.read_text()
                    assert 'TLSv1.2' in gs.log.read_text()
                    bad_name = relay(gs.port, outbound=dict(outbound, server_name='wrong.invalid'))
                    check('GOST '+cipher+' wrong SAN rejected', lambda: denied(bad_name.port))
                    no_identity = dict(outbound); no_identity.pop('certificate'); no_identity.pop('private_key')
                    no_identity_client = relay(gs.port, outbound=no_identity)
                    check('GOST '+cipher+' requires client certificate', lambda: denied(no_identity_client.port))
                    expired = relay(gs.port, outbound=dict(outbound, certificate=gost/'expired.pem', private_key=gost/'expired.key'))
                    check('GOST '+cipher+' expired client rejected', lambda: denied(expired.port))
                    # A normal TLS-only client must not negotiate a different cipher in GOST mode.
                    downgrade = relay(gs.port, outbound=dict(endpoints(rsa)[1], ca_file=gost/'ca.pem'))
                    check('GOST '+cipher+' has no standard TLS fallback', lambda: denied(downgrade.port))
        finally:
            if sys.exc_info()[0] is not None:
                for process in relays:
                    print(process.log.name + ':\n' + process.log.read_text()[-4000:], file=sys.stderr)
            for process in reversed(relays):
                process.close()
            echo.close()
    args.results.write_text(json.dumps({'passed': len(results), 'tests': results}, ensure_ascii=False, indent=2)+'\n')
    print('PASSED', len(results), flush=True)


if __name__ == '__main__':
    main()
