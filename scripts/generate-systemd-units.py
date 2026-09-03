#!/usr/bin/env python3
"""Generate isolated systemd units from socat-rust TOML relay profiles."""
from __future__ import annotations

import argparse
import os
import pathlib
import tomllib


UNIT = """[Unit]
Description=socat-rust relay {name}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={uid}
Group={uid}
ExecStart=/usr/local/bin/socat-rust --config /etc/socat-rust/relays.toml --relay {name}
Restart=on-failure
RestartSec=2s
TimeoutStopSec=10s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
RestrictAddressFamilies=AF_INET AF_INET6
ReadWritePaths=/var/log/socat-rust
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=pathlib.Path)
    parser.add_argument("output_dir", type=pathlib.Path)
    args = parser.parse_args()
    data = tomllib.loads(args.config.read_text(encoding="utf-8"))
    relays = data.get("relay", [])
    if not relays:
        raise SystemExit("configuration contains no relay profiles")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for relay in relays:
        name = relay["name"]
        uid = relay.get("uid")
        if uid is None:
            raise SystemExit(f"{name}: uid is required for systemd generation")
        if not isinstance(uid, int) or uid < 1:
            raise SystemExit(f"{name}: uid must be a positive integer")
        path = args.output_dir / f"socat-rust-{name}.service"
        path.write_text(UNIT.format(name=name, uid=uid), encoding="utf-8")
        os.chmod(path, 0o644)
        print(path)


if __name__ == "__main__":
    main()
