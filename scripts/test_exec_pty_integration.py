#!/usr/bin/env python3
"""Bounded localhost integration tests for EXEC/PTY endpoints over mTLS."""
import argparse
import json
import os
import pty
import select
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time


def command(args):
    return subprocess.run([str(x) for x in args], check=True, capture_output=True, timeout=20)


def unused_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class Relay:
    def __init__(self, binary, directory, process, inbound, extra=''):
        self.port = unused_port()
        name = 'relay-' + str(self.port)
        self.config = directory / (name + '.toml')
        self.log = directory / (name + '.log')
        text = f'''[[relay]]
name = "{name}"
listen = "127.0.0.1:{self.port}"
pid_file = "{directory / (name + '.lock')}"
max_connections = 4
{extra}
[relay.inbound_tls]
'''
        for key, value in inbound.items():
            text += key + ' = ' + json.dumps(str(value) if isinstance(value, Path) else value) + '\n'
        text += '\n[relay.process]\n'
        for key, value in process.items():
            if isinstance(value, dict):
                inner = ', '.join(k + ' = ' + json.dumps(v) for k, v in value.items())
                text += key + ' = { ' + inner + ' }\n'
            else:
                text += key + ' = ' + json.dumps(value) + '\n'
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

    def text(self):
        self.output.flush()
        return self.log.read_text()

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(3)
        self.output.close()


def rsa_pki(directory):
    command(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
             '-subj', '/CN=Synthetic EXEC PTY CA', '-keyout', directory/'ca.key', '-out', directory/'ca.pem'])
    extension = directory/'leaf.ext'
    extension.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n')
    for name in ('server', 'client'):
        command(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN='+name,
                 '-keyout', directory/(name+'.key'), '-out', directory/(name+'.csr')])
        command(['openssl', 'x509', '-req', '-in', directory/(name+'.csr'), '-CA', directory/'ca.pem',
                 '-CAkey', directory/'ca.key', '-CAcreateserial', '-days', '2', '-extfile', extension,
                 '-out', directory/(name+'.pem')])


def context(directory, client=True):
    ctx = ssl.create_default_context(cafile=str(directory/'ca.pem'))
    if client:
        ctx.load_cert_chain(directory/'client.pem', directory/'client.key')
    return ctx


def connect(port, ctx):
    sock = socket.create_connection(('127.0.0.1', port), timeout=6)
    return ctx.wrap_socket(sock, server_hostname='localhost')


def read_until(stream, needle, timeout=6):
    stream.settimeout(timeout)
    data = b''
    deadline = time.monotonic() + timeout
    while needle not in data:
        if time.monotonic() > deadline:
            raise AssertionError(f'{needle!r} not seen in {data[-400:]!r}')
        block = stream.recv(65536)
        if not block:
            break
        data += block
    assert needle in data, (needle, data[-400:])
    return data


def children(pid):
    found = []
    for task in Path(f'/proc/{pid}/task').iterdir():
        path = task / 'children'
        if path.exists():
            found += [int(value) for value in path.read_text().split()]
    return found


def zombies(pid):
    found = []
    for child in children(pid):
        try:
            if Path(f'/proc/{child}/stat').read_text().split()[2] == 'Z':
                found.append(child)
        except FileNotFoundError:
            pass
    return found


def ptmx_fds(pid):
    found = []
    for fd in Path(f'/proc/{pid}/fd').iterdir():
        try:
            if os.readlink(fd).startswith('/dev/ptmx'):
                found.append(fd)
        except FileNotFoundError:
            pass
    return found


def clean(pid):
    assert not zombies(pid), zombies(pid)
    assert not ptmx_fds(pid), ptmx_fds(pid)


def wait_clean(pid, timeout=6):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not zombies(pid) and not ptmx_fds(pid):
            return
        time.sleep(0.05)
    clean(pid)


def recv_exact(stream, count, timeout=6):
    stream.settimeout(timeout)
    data = b''
    while len(data) < count:
        block = stream.recv(count - len(data))
        if not block:
            raise AssertionError(f'EOF после {len(data)} из {count} байт')
        data += block
    return data


def send_frame(stream, kind, payload=b''):
    stream.sendall(bytes([kind]) + len(payload).to_bytes(4, 'big') + payload)


def recv_frame(stream, timeout=6):
    header = recv_exact(stream, 5, timeout)
    return header[0], recv_exact(stream, int.from_bytes(header[1:], 'big'), timeout)


def read_pty(fd, needle, timeout=8):
    data = b''
    deadline = time.monotonic() + timeout
    while needle not in data:
        if time.monotonic() > deadline:
            raise AssertionError(f'{needle!r} not seen in {data[-300:]!r}')
        ready, _, _ = select.select([fd], [], [], 0.2)
        if ready:
            data += os.read(fd, 4096)
    return data


def alive(pid):
    return Path(f'/proc/{pid}').exists()


def wait_dead(pid, timeout=8):
    deadline = time.monotonic() + timeout
    while alive(pid):
        if time.monotonic() > deadline:
            raise AssertionError(f'pid {pid} survived')
        time.sleep(0.05)


def expect_eof(stream, timeout=8):
    stream.settimeout(timeout)
    deadline = time.monotonic() + timeout
    while True:
        try:
            if not stream.recv(65536):
                return
        except (ssl.SSLEOFError, ConnectionResetError):
            return
        if time.monotonic() > deadline:
            raise AssertionError('connection did not close')


def read_all(stream, timeout=8):
    stream.settimeout(timeout)
    data = b''
    while block := stream.recv(65536):
        data += block
    return data


def read_exact(stream, size, timeout=15):
    stream.settimeout(timeout)
    data = b''
    while len(data) < size:
        block = stream.recv(min(65536, size - len(data)))
        if not block:
            break
        data += block
    return data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--results', type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve()
    results = []
    relays = []
    with tempfile.TemporaryDirectory(prefix='socat-exec-pty-') as tmp:
        root = Path(tmp)
        pki = root/'pki'; pki.mkdir(); rsa_pki(pki)
        inbound = dict(mode='tls', certificate=pki/'server.pem', private_key=pki/'server.key',
                       client_ca=pki/'ca.pem', handshake_timeout_seconds=2)
        ctx = context(pki)

        def relay(process, **extra):
            result = Relay(binary, root, process, inbound, **extra)
            relays.append(result)
            return result

        def check(label, operation):
            operation()
            results.append(label)
            print('PASS', label, flush=True)

        try:
            cat = relay(dict(command='/bin/cat', terminate_grace_seconds=1))
            payload = b'exec binary\x00\xff' * 4096

            def binary_roundtrip():
                with connect(cat.port, ctx) as stream:
                    stream.sendall(payload)
                    assert read_exact(stream, len(payload)) == payload
            check('exec binary stdin/stdout roundtrip', binary_roundtrip)

            large = relay(dict(command='/usr/bin/head', args=['-c', '1048576', '/dev/zero']))
            def large_stdout():
                with connect(large.port, ctx) as stream:
                    assert len(read_exact(stream, 1048576)) == 1048576
            check('exec large stdout', large_stdout)

            mixed = relay(dict(command='/bin/sh', args=['-c', 'echo out; echo err >&2'], stderr='client'))
            def stderr_to_client():
                with connect(mixed.port, ctx) as stream:
                    data = read_all(stream)
                    assert b'out' in data and b'err' in data
            check('exec stderr policy client', stderr_to_client)

            failing = relay(dict(command='/bin/sh', args=['-c', 'exit 7']))
            def nonzero_status():
                with connect(failing.port, ctx) as stream:
                    assert stream.recv(1) == b''
                deadline = time.monotonic() + 5
                while 'exit_status=7' not in failing.text():
                    if time.monotonic() > deadline:
                        raise AssertionError(failing.text())
                    time.sleep(0.05)
                assert 'завершён с ошибкой' in failing.text()
            check('exec nonzero exit status logged', nonzero_status)

            console = relay(dict(command='/bin/sh', args=['-i'], terminate_grace_seconds=1,
                                  terminal=dict(rows=24, columns=80)), extra='endpoint = "pty"')

            idle = relay(dict(command='/bin/cat', idle_timeout_seconds=1, terminate_grace_seconds=1))
            def idle_timeout():
                start = time.monotonic()
                with connect(idle.port, ctx) as stream:
                    assert stream.recv(1) == b''
                elapsed = time.monotonic() - start
                assert 1 <= elapsed < 6, elapsed
                assert 'простой сессии истёк' in idle.text()
            check('exec idle timeout terminates process', idle_timeout)

            def requires_mtls():
                before = cat.text().count('процесс запущен')
                plain = context(pki, client=False)
                try:
                    with connect(cat.port, plain) as stream:
                        stream.sendall(b'x')
                        stream.recv(1)
                except (ssl.SSLError, OSError):
                    pass
                time.sleep(0.2)
                assert cat.text().count('процесс запущен') == before
            check('exec requires client certificate', requires_mtls)

            slow = relay(dict(command='/bin/sh', args=['-c', 'seq 1 20000']))
            def slow_client():
                with connect(slow.port, ctx) as stream:
                    data = b''
                    while True:
                        chunk = stream.recv(512)
                        if not chunk:
                            break
                        data += chunk
                        time.sleep(0.002)
                assert data.split() == [str(i).encode() for i in range(1, 20001)]
            check('exec slow client keeps all data', slow_client)

            repeated = relay(dict(command='/bin/sh', args=['-c', 'id -u']))
            def repeated_sessions():
                for _ in range(5):
                    with connect(repeated.port, ctx) as stream:
                        assert read_all(stream, 8).strip() == str(os.getuid()).encode()
            check('exec repeated sessions', repeated_sessions)

            orphan = relay(dict(command='/bin/sh', args=['-c', 'sleep 300 & echo $!']))
            def leader_exit_sweeps():
                with connect(orphan.port, ctx) as stream:
                    pid = int(read_all(stream, 6).strip())
                wait_dead(pid, 6)
            check('leader exit kills background job', leader_exit_sweeps)

            orphan_close = relay(dict(command='/bin/sh',
                                      args=['-c', 'sleep 300 & echo $!; sleep 0.5'],
                                      terminate_grace_seconds=1))
            def client_close_sweeps():
                stream = connect(orphan_close.port, ctx)
                stream.settimeout(6)
                buf = b''
                while b'\n' not in buf:
                    buf += stream.recv(64)
                pid = int(buf.split(b'\n')[0])
                stream.close()
                # Лидер выйдет сам в пределах grace; фоновый sleep — нет.
                wait_dead(pid, 6)
            check('client close kills background job', client_close_sweeps)

            shell = relay(dict(command='/bin/sh', args=['-i'], stderr='client',
                               terminal=dict(rows=24, columns=80, term='xterm-256color')),
                          extra='endpoint = "pty"')
            def pty_session():
                with connect(shell.port, ctx) as stream:
                    read_until(stream, b'$ ', 8)
                    stream.sendall(b'stty size\n')
                    read_until(stream, b'24 80')
                    stream.sendall(b'echo marker-$((1+1))\n')
                    read_until(stream, b'marker-2')
                    stream.sendall(b'sleep 30\n')
                    time.sleep(0.4)
                    stream.sendall(b'\x03')
                    stream.sendall(b'echo after-$((2+2))\n')
                    read_until(stream, b'after-4', 8)
                    stream.sendall(b'exit\n')
                    expect_eof(stream)
            check('pty shell prompt, size, Ctrl-C, exit', pty_session)

            pty_cat = relay(dict(command='/bin/cat', terminal=dict(rows=24, columns=80)),
                            extra='endpoint = "pty"')
            def background_pid(stream):
                stream.sendall(b'sleep 300 & echo PID=$!\n')
                # Ждём первую строку, состоящую только из цифр: эхо команды и
                # уведомление job control содержат другой текст.
                stream.settimeout(8)
                buf = b''
                while True:
                    while b'\n' not in buf:
                        buf += stream.recv(256)
                    line, buf = buf.split(b'\n', 1)
                    if line.startswith(b'PID='):
                        pid = int(line[4:])
                        assert alive(pid), pid
                        return pid

            cleanup = relay(dict(command='/bin/sh', args=['-i'], terminate_grace_seconds=1,
                                 terminal=dict(rows=24, columns=80)), extra='endpoint = "pty"')
            def disconnect_cleanup():
                with connect(cleanup.port, ctx) as stream:
                    read_until(stream, b'$ ')
                    pid = background_pid(stream)
                wait_dead(pid)
                wait_clean(cleanup.process.pid)
            check('disconnect kills shell job', disconnect_cleanup)

            stopping = relay(dict(command='/bin/sh', args=['-i'], terminate_grace_seconds=1,
                                  terminal=dict(rows=24, columns=80)), extra='endpoint = "pty"')
            def sigterm_cleanup():
                stream = connect(stopping.port, ctx)
                read_until(stream, b'$ ')
                pid = background_pid(stream)
                stopping.close()
                wait_dead(pid)
                stream.close()
            check('SIGTERM kills shell job', sigterm_cleanup)

            console = relay(dict(command='/bin/sh', args=['-i'], terminate_grace_seconds=1,
                                  terminal=dict(rows=24, columns=80)), extra='endpoint = "pty"')

            idle = relay(dict(command='/bin/sh', args=['-i'], idle_timeout_seconds=1,
                              terminate_grace_seconds=1,
                              terminal=dict(rows=24, columns=80)), extra='endpoint = "pty"')
            def idle_cleanup():
                with connect(idle.port, ctx) as stream:
                    read_until(stream, b'$ ')
                    pid = background_pid(stream)
                    wait_dead(pid, 12)
                wait_clean(idle.process.pid)
            check('idle timeout kills shell job', idle_cleanup)

            def console_protocol():
                with connect(console.port, ctx) as stream:
                    stream.sendall(b'\0SRC1')
                    send_frame(stream, 2, (40).to_bytes(2, 'big') + (100).to_bytes(2, 'big'))
                    data = b''
                    while b'$ ' not in data:
                        kind, payload = recv_frame(stream)
                        assert kind == 1, kind
                        data += payload
                    send_frame(stream, 1, b'stty size\n')
                    while b'40 100' not in data:
                        kind, payload = recv_frame(stream)
                        assert kind == 1, kind
                        data += payload
                    send_frame(stream, 1, b'exit\n')
                    while True:
                        kind, payload = recv_frame(stream)
                        if kind == 3:
                            assert int.from_bytes(payload, 'big') == 0
                            break
                        assert kind == 1, kind
                wait_clean(console.process.pid)
            check('console protocol resize and exit status', console_protocol)

            def console_exit_frame():
                with connect(console.port, ctx) as stream:
                    stream.sendall(b'\0SRC1')
                    data = b''
                    while b'$ ' not in data:
                        kind, payload = recv_frame(stream)
                        assert kind == 1, kind
                        data += payload
                    send_frame(stream, 3, (0).to_bytes(4, 'big'))
                    while True:
                        kind, payload = recv_frame(stream)
                        if kind == 3:
                            assert int.from_bytes(payload, 'big') == 0
                            break
                        assert kind == 1, kind
                wait_clean(console.process.pid)
            check('console EXIT frame delivers EOF to shell', console_exit_frame)

            def console_binary():
                master, slave = pty.openpty()
                process = subprocess.Popen(
                    [str(binary), 'console', f'127.0.0.1:{console.port}',
                     '--ca', str(pki/'ca.pem'), '--cert', str(pki/'client.pem'),
                     '--key', str(pki/'client.key'), '--server-name', 'localhost'],
                    stdin=slave, stdout=slave, stderr=slave)
                os.close(slave)
                try:
                    # POSIX shells need not use the same prompt. Prove the
                    # interactive path with a command/response marker instead.
                    os.write(master, b'echo console-$((3+4))\n')
                    read_pty(master, b'console-7')
                    os.write(master, b'exit\n')
                    assert process.wait(8) == 0, process.returncode
                finally:
                    os.close(master)
                    if process.poll() is None:
                        process.kill()
                        process.wait()
                wait_clean(console.process.pid)
            check('console binary end-to-end', console_binary)

            limited = relay(dict(command='/bin/sh', args=['-c', 'ulimit -a'], max_processes=100))
            def process_limit():
                with connect(limited.port, ctx) as stream:
                    output = read_all(stream, 6)
                    fields = [row.split() for row in output.splitlines()]
                    line = [row for row in fields if row[:1] == [b'process']
                            or row[:3] == [b'max', b'user', b'processes']]
                    assert line and line[0][-1] == b'100', output
            check('max_processes sets RLIMIT_NPROC', process_limit)

            timed = relay(dict(command='/bin/sh', args=['-i'], max_duration_seconds=1,
                               terminate_grace_seconds=1,
                               terminal=dict(rows=24, columns=80)), extra='endpoint = "pty"')
            def duration_limit():
                with connect(timed.port, ctx) as stream:
                    read_until(stream, b'$ ')
                    pid = background_pid(stream)
                    wait_dead(pid, 12)
                wait_clean(timed.process.pid)
            check('max duration kills session', duration_limit)

            def pty_ctrl_d():
                with connect(pty_cat.port, ctx) as stream:
                    stream.sendall(b'pty\n')
                    read_until(stream, b'pty')
                    stream.sendall(b'\x04')
                    expect_eof(stream)
            check('pty Ctrl-D delivers EOF', pty_ctrl_d)
        finally:
            for item in relays:
                item.close()
    args.results.write_text(json.dumps(results, ensure_ascii=False, indent=2) + '\n')
    print('ALL PASS', flush=True)


if __name__ == '__main__':
    main()
