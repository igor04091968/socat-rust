# Optional TLS and GOST TLS

Version 0.1.12 adds independent inbound and outbound TLS endpoints. Profiles
without either TLS table continue to relay TCP bytes, including end-to-end
TLS encrypted by the original endpoints. No upgrade or protocol sniffing is used.

## Build features

- No features: plain TCP binary. Any TLS configuration is rejected.
- `--features tls`: standard TLS 1.2/1.3, optional mutual authentication.
- `--features tls-gost`: standard TLS plus statically linked GOST Engine.
  GOST is selected explicitly per endpoint and restricted to TLS 1.2.
- `legacy-kernel` does not support TLS endpoints; such profiles are rejected.

`config-check` validates all configured profiles and, in TLS builds, loads the
CA/certificate/key material and checks key matching. It opens no network sockets.
Unknown relay and TLS fields are rejected, including insecure `verify=false`.
TLS handshakes have an explicit timeout (default 10 seconds, range 1..120).

## Standard TLS: authenticate clients before forwarding

```toml
[[relay]]
name = "secure-example"
listen = "127.0.0.1:18000"
upstream = "127.0.0.1:18001"
allow = ["127.0.0.1/32"]
max_connections = 4

[relay.inbound_tls]
mode = "tls"
certificate = "/etc/socat-rust/pki/server-chain.pem"
private_key = "/etc/socat-rust/pki/server.key"
client_ca = "/etc/socat-rust/pki/client-ca.pem"
handshake_timeout_seconds = 10
```

Presence of `client_ca` requires a valid trusted client certificate. Omitting it
allows ordinary TLS clients without a certificate. Inbound TLS authentication
finishes before opening the upstream connection. This is CA-based admission,
not a separate per-certificate subject/serial authorization policy.

## Outbound TLS or GOST TLS

```toml
[relay.outbound_tls]
mode = "gost"
gost_cipher = "kuznyechik"
ca_file = "/etc/socat-rust/pki/upstream-ca.pem"
server_name = "upstream.example.internal"
certificate = "/etc/socat-rust/pki/client-chain.pem"
private_key = "/etc/socat-rust/pki/client.key"
handshake_timeout_seconds = 10
```

Use this table under a complete `[[relay]]` profile. `certificate` and
`private_key` are optional together, for upstream mutual authentication.
`ca_file` and `server_name` are mandatory. Verification checks the certificate
chain, time validity and the configured DNS/IP identity. The explicit CA bundle
replaces the default client trust store; no insecure verification switch exists.

Inbound and outbound can each independently be plain TCP, standard TLS, or
GOST TLS. To accept GOST clients, use `mode = "gost"` and `gost_cipher` inside
`[relay.inbound_tls]` with a suitable GOST certificate/private key.

| `gost_cipher` | OpenSSL cipher name | Wire ID |
|---|---|---|
| `kuznyechik` (default) | GOST2012-KUZNYECHIK-KUZNYECHIKOMAC | 0xC100 |
| `magma` | GOST2012-MAGMA-MAGMAOMAC | 0xC101 |
| `gost28147` | IANA-GOST2012-GOST8912-GOST8912 | 0xC102 |
| `legacy28147` | LEGACY-GOST2012-GOST8912-GOST8912 | 0xFF85 |

Only the selected cipher is offered in GOST mode. NULL encryption, ordinary
TLS cipher fallback and plaintext fallback are not permitted. The legacy
0xFF85 suite requires explicit selection. GOST TLS 1.3 is not implemented.
Compatibility with a particular CryptoPro/other remote endpoint must be checked
against its actual versions, cipher suites, certificate profile and key storage.
This implementation is not a certified SKZI and does not embed CryptoPro CSP.

## Keys, privileges and logs

Certificates, CA bundles and keys are deployment data, not embedded in binaries.
Use absolute paths, particularly for `--daemon` (which changes cwd to `/`).
Runtime keys must be readable by the configured relay UID. Prefer 0600 with the
relay owning its key, or a narrowly assigned group; do not make keys world-readable.
No test CA or test key belongs in production. Encrypted key containers/token/CSP
key handles and CRL/OCSP revocation configuration are not supported in this release.
TLS payload logging is prohibited even if `verbose_payload_logging=true` is set.
Negotiated protocol/cipher and verification failures are logged, not private keys.

TLS handshake failures terminate the accepted connection and release its slot.
Existing per-attempt TCP connect timeouts and bounded retry backoff still apply before an outbound handshake;
there is no repeated TLS downgrade/retry or replay of application payloads.

## Reproducible static Linux build

Build on the notebook, not on gw2:

```sh
bash scripts/fetch-tls-native.sh
bash scripts/build-tls-native.sh
bash scripts/build-static-tls.sh
```

Dependencies: Rust with x86_64-unknown-linux-musl, musl-gcc, CMake >=3.18,
GNU make, Perl, Linux UAPI development headers, binutils, file, Python 3, git
and curl. The integration harness also needs a system openssl CLI for synthetic
RSA certificates; the relay does not need it. The native build
uses two jobs and copies UAPI headers into its isolated toolchain directory.
No system OpenSSL files or configuration are replaced.

Pinned OpenSSL: 3.5.9, official archive SHA256
`603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a`.
Pinned GOST Engine commit: `af2b7e69e855572202420ffc36bae06ccd70796b`.
The engine is built with `GOST_BUILD_STATIC_ENGINE=ON`; no `gost.so`, provider
DSO or external `openssl` executable is used by the relay at runtime.
The upstream engine emits a warning about the TLS 1.3 TLSTREE extension absent
from unpatched OpenSSL. This release negotiates GOST TLS 1.2 only.

Check the final executable with `file`, `readelf -l` (no INTERP) and
`readelf -d` (no NEEDED). Static linking does not remove the need to ship
certificate/key/config data and update/rebuild cryptographic dependencies.

## Validation and deployment boundary

Use the integration harness only with synthetic keys on localhost:

```sh
python3 scripts/test_tls_integration.py --binary /path/to/tls-binary \
  --plain-binary /path/to/plain-binary --gost-fixture /path/to/gost-fixture \
  --results /tmp/tls-results.json
```

The GOST PKI fixture generator source is `tests/gost_fixture.c`. It is a test
helper, not installed with the relay. Standard TLS also interoperates with
Python's independent system TLS client. GOST engine interoperability with
external production services/CryptoPro is a separate acceptance step.

This release is prepared for Linux x86_64/Astra. The previous FreeBSD 0.1.11
artifact is not upgraded automatically; TLS/GOST FreeBSD runtime is not claimed.
Existing Astra production binaries/configuration/services remain unchanged
until a separate deployment instruction. Preserve the old binary/config for
rollback and test a new profile before enabling TLS on a working connector.
