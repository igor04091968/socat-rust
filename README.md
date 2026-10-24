# socat-rust

Linux/Debian-first TCP relay for replacing the current `socat` forwarding
profiles with explicit configuration, bounded concurrency and systemd
isolation.

Optional TLS 1.2/1.3, mutual TLS, and explicit GOST TLS 1.2 endpoints are described in [docs/TLS_GOST.md](docs/TLS_GOST.md). TLS is disabled unless an endpoint table is configured and the binary includes the corresponding build feature.

Инструкция на русском: **[запуск TCP, TLS, ГОСТ, daemon и systemd](docs/RUNNING_RU.md)**.

Встроенный генератор в v0.1.13: **[ключи, CSR и самоподписанные сертификаты TLS/ГОСТ](docs/PKI_RU.md)**.

## Initial supported profile

- IPv4 TCP listener and IPv4 TCP upstream;
- bind to an explicit local address;
- source ACL in CIDR notation;
- per-profile `backlog` and `max_connections`;
- separate client/upstream TCP keepalive settings;
- EOF grace timeout (`-t` equivalent);
- upstream connect retry with bounded exponential backoff (`forever`);
- optional payload logging (`-v`, disabled by default);
- separate process and UID per relay profile through systemd.
- корректное завершение по SIGTERM/Ctrl-C с прекращением приема новых соединений.

Each relay runs as a separate process. The shipped systemd template starts
it as root; the daemon prepares logs and locks, then drops to the configured
numeric UID/GID before opening sockets. Supplementary groups are cleared.

`config.example.toml` contains the observed `bnk2450001`–`bnk2450037` profiles
(with missing ports omitted). Add a `[[relay]]` block and start its instance
as `socat-rust@<name>.service`; the Rust binary does not need changing.

## Validate and run

```bash
cargo test
cargo run -- --config config.example.toml config-check
cargo run -- --config config.example.toml --relay bnk2450034
```

## Build profiles

The project contains two RustRover run configurations and matching Cargo
aliases:

```bash
# New Debian/Linux: Tokio implementation
cargo build-debian
# target/release/socat-rust

# CentOS 5 / kernel 2.6.18: legacy blocking implementation, static musl
cargo build-centos5
# target/x86_64-unknown-linux-musl/release/socat-rust
```

In RustRover select `build_debian` or `build_centos5` in the Run
configuration list. Both profiles use the same source and configuration
format; only the runtime/build target differs.

## Install and operate

Use the static release binaries and the shipped `socat-rust@.service` template.
See [the running guide](docs/RUNNING_RU.md) for checksum verification, complete
configuration examples, UID/key permissions, foreground/daemon operation,
systemd installation and the connector manager.

The all-feature `socat-rust-linux-amd64-tls-gost-static` binary supports plain
TCP, ordinary TLS and GOST through per-endpoint configuration. Ordinary TLS
negotiates 1.2/1.3; forcing a specific version through configuration is not
implemented. GOST is TLS 1.2 only. Restart the profile after changing its config.

CentOS 5/kernel 2.6.18 requires the separate TCP-only `legacy-kernel` variant;
use the legacy artifact from [v0.1.11](https://github.com/igor04091968/socat-rust/releases/tag/v0.1.11).

## Mapping of the current profile

The command:

```text
socat ... TCP4-LISTEN:8034,bind=10.34.0.1,su=2450034,fork,max-children=1,backlog=1,range=10.19.63.0/24,reuseaddr,keepalive,keepidle=15,keepintvl=15,keepcnt=8,forever TCP4:172.22.22.34:8000,keepalive,keepidle=150,keepintvl=60,keepcnt=2,forever
```

maps to the `bnk2450034` example profile. `-lf` becomes `log_file`, `-v` is
`verbose_payload_logging`, and `su=2450034` becomes `uid = 2450034`.

The daemon also applies `uid` itself before creating the listener and the
upstream socket. This is required on systems where firewall rules match the
process UID. If the daemon is started by hand, start it as root so it can drop
privileges, for example:

```bash
sudo ./socat-rust-centos5-v0.1.11 \
  --config /etc/socat-rust/relays.toml --relay bnk2450034
```

The process then runs with effective UID/GID `2450034`. Root prepares the log
file before dropping privileges; TLS material must be readable by the relay UID. Starting as the wrong
non-root account is rejected instead of silently creating firewall traffic
under the wrong UID.

Для совместимости с существующим Monit можно задать `pid_file`, например
`pid_file = "/tmp/bnk2450014.lock"`. Файл содержит PID и одновременно
удерживается через kernel lock. Старый PID после падения не препятствует
повторному запуску: блокировка освобождается ядром автоматически.

Проверку Monit `if children > 1` для `socat-rust` переносить не следует:
relay использует потоки, а не дочерние процессы. Ограничение соединений
задаётся параметром `max_connections`.

## Safety notes

Payload logging can expose credentials and personal data and can grow logs
quickly. Keep it disabled in production unless it is temporarily required for
diagnosis, with logrotate configured separately.
