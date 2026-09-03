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

## Safety notes

Payload logging can expose credentials and personal data and can grow logs
quickly. Keep it disabled in production unless it is temporarily required for
diagnosis, with logrotate configured separately.
