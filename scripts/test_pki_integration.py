#!/usr/bin/env python3
"""Offline PKI CLI and bounded loopback acceptance with synthetic keys only."""
import argparse
import contextlib
import json
import os
from pathlib import Path
import ssl
import stat
import subprocess
import tempfile
from test_tls_integration import Echo, Relay, exchange


def invoke(args, success=True):
    completed = subprocess.run([str(x) for x in args], capture_output=True, timeout=30,
                               env={**os.environ, 'OPENSSL_CONF': '/dev/null' if Path(str(args[0])).name == 'openssl' else '/nonexistent/synthetic-no-config'})
    assert (completed.returncode == 0) == success, (args, completed.returncode, completed.stderr.decode(errors='replace'))
    return completed


def pki(binary, *args, success=True):
    # Missing config proves PKI dispatch precedes relay configuration loading.
    return invoke([binary, '--config', '/nonexistent/pki-does-not-use-config', 'pki', *args], success)


def certificate(binary, directory, algorithm, usage='both'):
    directory.mkdir()
    key, cert, csr = [directory / name for name in ('identity.key', 'identity.pem', 'identity.csr')]
    pki(binary, 'keygen', '--algorithm', algorithm, '--out', key)
    identity = ['--cn', 'Synthetic identity', '--dns', 'localhost', '--dns', 'relay.example.org',
                '--ip', '127.0.0.1', '--ip', '::1', '--usage', usage]
    pki(binary, 'csr', '--key', key, '--out', csr, *identity)
    pki(binary, 'self-signed', '--key', key, '--out', cert, '--days', '2', *identity)
    for output in (key, cert, csr):
        assert stat.S_IMODE(output.stat().st_mode) == 0o600
    decoded = ssl._ssl._test_decode_cert(str(cert))
    sans = set(decoded['subjectAltName'])
    assert {('DNS', 'localhost'), ('DNS', 'relay.example.org'), ('IP Address', '127.0.0.1'),
            ('IP Address', '0:0:0:0:0:0:0:1')} <= sans, sans
    assert abs(ssl.cert_time_to_seconds(decoded['notAfter']) - ssl.cert_time_to_seconds(decoded['notBefore']) - 172800) < 5
    assert decoded['issuer'] == decoded['subject']
    if algorithm in ('rsa3072', 'ecdsa-p256'):
        invoke(['openssl', 'req', '-in', csr, '-verify', '-noout'])
        invoke(['openssl', 'verify', '-check_ss_sig', '-purpose', 'sslserver', '-CAfile', cert, cert])
        text = invoke(['openssl', 'x509', '-in', cert, '-text', '-noout']).stdout.decode()
        assert 'CA:FALSE' in text and 'TLS Web Server Authentication' in text
        assert 'TLS Web Client Authentication' in text
    return key, cert, csr


def rejected_exchange(port):
    try:
        exchange(port)
    except (OSError, AssertionError):
        return
    raise AssertionError('unexpected successful TLS exchange')


def handshake(binary, directory, server_files, client_files, mode, cipher=None):
    with contextlib.ExitStack() as stack:
        echo = Echo(directory); stack.callback(echo.close)
        server_key, server_cert, _ = server_files
        client_key, client_cert, _ = client_files
        inbound = dict(mode=mode, certificate=server_cert, private_key=server_key,
                       client_ca=client_cert, handshake_timeout_seconds=2)
        outbound = dict(mode=mode, ca_file=server_cert, server_name='localhost',
                        certificate=client_cert, private_key=client_key, handshake_timeout_seconds=2)
        if cipher:
            inbound['gost_cipher'] = outbound['gost_cipher'] = cipher
        server = Relay(binary, directory, echo.port, inbound=inbound); stack.callback(server.close)
        client = Relay(binary, directory, server.port, outbound=outbound); stack.callback(client.close)
        exchange(client.port)
        wrong = Relay(binary, directory, server.port, outbound=dict(outbound, server_name='wrong.invalid'))
        stack.callback(wrong.close); rejected_exchange(wrong.port)
        if mode == 'tls':
            independent = ssl.create_default_context(cafile=str(server_cert))
            independent.load_cert_chain(client_cert, client_key)
            exchange(server.port, independent)
        else:
            assert 'TLSv1.2' in server.log.read_text()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--tls-binary', type=Path, required=True)
    parser.add_argument('--plain-binary', type=Path, required=True)
    parser.add_argument('--results', type=Path, required=True)
    args = parser.parse_args()
    binary, tls, plain = [p.resolve() for p in (args.binary, args.tls_binary, args.plain_binary)]
    results = []
    def passed(label): results.append(label)
    with tempfile.TemporaryDirectory(prefix='socat-pki-acceptance-') as temporary:
        root = Path(temporary)
        for algorithm in ('rsa3072', 'ecdsa-p256', 'gost2012-256', 'gost2012-512'):
            files = certificate(binary, root/algorithm, algorithm)
            passed(algorithm + ': key/CSR/self-signed PEM, permissions, SANs and lifetime')
            key, cert, csr = files
            for action, output in [('keygen', key), ('csr', csr), ('self-signed', cert)]:
                before = output.read_bytes()
                opts = ['--out', output] if action == 'keygen' else ['--key', key, '--out', output, '--cn', 'test', '--dns', 'localhost']
                pki(binary, action, *opts, success=False)
                assert output.read_bytes() == before
            passed(algorithm + ': all commands refuse existing files without mutation')
            if algorithm == 'gost2012-512':
                # 512-bit signing is available for PKI. Relay GOST TLS suites
                # use the 256-bit authentication profile; do not claim 512 TLS.
                continue
            mode = 'gost' if algorithm.startswith('gost') else 'tls'
            client = certificate(binary, root/(algorithm+'-client'), algorithm)
            ciphers = ('kuznyechik', 'magma', 'gost28147', 'legacy28147') if mode == 'gost' else (None,)
            for cipher in ciphers:
                handshake(binary, root, files, client, mode, cipher)
                passed(algorithm + ': mTLS loopback + wrong SAN rejected' + (' / '+cipher if cipher else ' / independent Python TLS'))
        files = certificate(tls, root/'tls-only', 'ecdsa-p256')
        passed('TLS-only binary generates and signs ordinary TLS material')
        key, cert, csr = files
        for algorithm in ('gost2012-256', 'gost2012-512'):
            out = root/(algorithm+'.rejected')
            pki(tls, 'keygen', '--algorithm', algorithm, '--out', out, success=False)
            assert not out.exists()
        out = root/'plain.rejected'
        pki(plain, 'keygen', '--out', out, success=False)
        assert not out.exists()
        passed('feature gates reject GOST in TLS-only and PKI in plain binaries')
        for action in ('csr', 'self-signed'):
            for bad_args in [[], ['--dns', 'good.org,IP:1.2.3.4'], ['--dns', '@section'],
                             ['--dns', 'bad\nname'], ['--dns', '127.0.0.1'], ['--dns', '-bad.org']]:
                out = root/'invalid.pem'
                pki(binary, action, '--key', key, '--out', out, '--cn', 'test', *bad_args, success=False)
                assert not out.exists()
        passed('missing SAN and malformed/injected SANs are rejected before output')
        for days in ('0', '3651', '-1', '4294967296'):
            pki(binary, 'self-signed', '--key', key, '--out', root/'days.pem', '--cn', 'test', '--dns', 'localhost', '--days', days, success=False)
        assert not (root/'days.pem').exists()
        passed('invalid certificate lifetime rejected')
        target=root/'target'; target.write_bytes(b'preserve')
        link=root/'link'; link.symlink_to(target)
        pki(binary,'keygen','--algorithm','ecdsa-p256','--out',link,success=False)
        assert target.read_bytes()==b'preserve' and link.is_symlink()
        dangling=root/'dangling'; dangling.symlink_to(root/'absent')
        pki(binary,'keygen','--algorithm','ecdsa-p256','--out',dangling,success=False)
        assert not (root/'absent').exists()
        passed('symlink and dangling-symlink outputs rejected')
        before=key.read_bytes()
        pki(binary,'self-signed','--key',key,'--out',key,'--cn','test','--dns','localhost',success=False)
        assert key.read_bytes()==before
        passed('key input cannot be overwritten by certificate output')
        encrypted=root/'encrypted.key'
        invoke(['openssl','pkey','-in',key,'-aes-256-cbc','-passout','pass:synthetic-test-only','-out',encrypted])
        pki(binary,'csr','--key',encrypted,'--out',root/'encrypted.csr','--cn','client','--usage','client',success=False)
        assert not (root/'encrypted.csr').exists()
        passed('encrypted input fails without prompt or output')
        for flag in ('--daemon','--relay'):
            opts=[flag] if flag=='--daemon' else [flag,'demo']
            invoke([binary,*opts,'pki','keygen','--out',root/'flags.key'],False)
        assert not (root/'flags.key').exists()
        passed('PKI rejects relay and daemon modes')
        pki(binary,'csr','--key',key,'--out',root/'client-only.csr','--cn','subject-only-client','--usage','client')
        passed('client-only CSR can omit SAN')
        isolated = subprocess.run([str(binary), 'pki', 'keygen', '--algorithm', 'ecdsa-p256',
                                   '--out', str(root/'no-external-tools.key')],
                                  env={**os.environ, 'PATH': '/nonexistent/no-external-tools',
                                       'OPENSSL_CONF': '/nonexistent/no-external-config',
                                       'OPENSSL_ENGINES': '/nonexistent/no-engines'},
                                  capture_output=True, timeout=15)
        assert isolated.returncode == 0, isolated.stderr
        passed('key generation needs no external openssl, engine DSO or config')
        # Exclusive create must arbitrate concurrent invocations, not just a precheck.
        out=root/'concurrent.key'
        commands=[subprocess.Popen([str(binary),'pki','keygen','--algorithm','ecdsa-p256','--out',str(out)],stdout=subprocess.PIPE,stderr=subprocess.PIPE) for _ in range(2)]
        for process in commands: process.communicate(timeout=15)
        assert sorted(p.returncode for p in commands)==[0,1]
        invoke(['openssl','pkey','-in',out,'-check','-noout'])
        passed('concurrent writers yield one valid key and one refusal')
    args.results.parent.mkdir(parents=True,exist_ok=True)
    args.results.write_text(json.dumps({'passed':len(results),'checks':results},indent=2)+'\n')
    print(json.dumps({'passed':len(results),'results':str(args.results)}))


if __name__ == '__main__':
    main()
