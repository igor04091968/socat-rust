# socat-rust

Linux/Debian-first TCP relay for replacing the current `socat` forwarding
profiles with explicit configuration, bounded concurrency and systemd
isolation.

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

The daemon intentionally does not implement `su` internally. Each generated
systemd unit runs directly as the configured UID, which avoids a shared root
process and gives every relay independent restart and failure isolation.

`config.example.toml` contains the currently observed `bnk2450001`–
`bnk2450037` profiles (with missing ports omitted) and is deliberately
configuration-driven: adding or changing a relay means editing one `[[relay]]`
block and regenerating its systemd unit. The process list can therefore be
extended without changing the Rust binary.

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

## Install multiple relays

Build and install the binary, copy a production config to
`/etc/socat-rust/relays.toml`, then generate isolated units:

```bash
cargo build --release
sudo install -m 0755 target/release/socat-rust /usr/local/bin/socat-rust
sudo install -d -m 0755 /etc/socat-rust /var/log/socat-rust
sudo install -m 0640 config.toml /etc/socat-rust/relays.toml
python3 scripts/generate-systemd-units.py \
  /etc/socat-rust/relays.toml /tmp/socat-rust-units
sudo install -m 0644 /tmp/socat-rust-units/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now socat-rust-bnk2450034.service
```

Для старых CentOS без совместимой glibc используйте статическую сборку:

```bash
cargo build --release --target x86_64-unknown-linux-musl
```

Для CentOS 5 с ядром 2.6.18 используйте legacy-вариант без static-PIE:

```bash
RUSTFLAGS='-C relocation-model=static' cargo build --release \
  --features legacy-kernel \
  --target x86_64-unknown-linux-musl
```

Выпуск `v0.1.7` содержит такой бинарь под именем `socat-rust-centos5`.
CentOS 5 не использует systemd, поэтому relay нужно запускать через SysV init,
supervisord или штатный механизм мониторинга процессов.

Before enabling a profile, stop its old `socat` process and verify that the
configured UID owns the log directory. Never enable both listeners on the same
address/port.

## Mapping of the current profile

The command:

```text
socat ... TCP4-LISTEN:8034,bind=10.34.0.1,su=2450034,fork,max-children=1,backlog=1,range=10.19.63.0/24,reuseaddr,keepalive,keepidle=15,keepintvl=15,keepcnt=8,forever TCP4:172.22.22.34:8000,keepalive,keepidle=150,keepintvl=60,keepcnt=2,forever
```

maps to the `bnk2450034` example profile. `-lf` becomes `log_file`, `-v` is
`verbose_payload_logging`, and `su=2450034` is represented by
`User=2450034`/`Group=2450034` in the generated unit.

The daemon also applies `uid` itself before creating the listener and the
upstream socket. This is required on systems where firewall rules match the
process UID. If the daemon is started by hand, start it as root so it can drop
privileges, for example:

```bash
sudo ./socat-rust-centos5-v0.1.6 \
  --config /etc/socat-rust/relays.toml --relay bnk2450034
```

The process then runs with effective UID/GID `2450034`; the log directory and
configured log file must be writable by that account. Starting as the wrong
non-root account is rejected instead of silently creating firewall traffic
under the wrong UID.

## Safety notes

Payload logging can expose credentials and personal data and can grow logs
quickly. Keep it disabled in production unless it is temporarily required for
diagnosis, with logrotate configured separately.
