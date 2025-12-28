#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


def now_tag() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, check=check, text=True, capture_output=True)


def start_bg(
    cmd: list[str],
    *,
    stdout_path: Path,
    env: dict[str, str] | None = None,
) -> subprocess.Popen:
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    f = stdout_path.open("w", encoding="utf-8")
    return subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT, env=env)


def kill_pid(pid: int, *, sig: int = signal.SIGTERM) -> None:
    try:
        os.kill(pid, sig)
    except ProcessLookupError:
        return


@dataclass(frozen=True)
class SessionPaths:
    dir: Path
    server_log: Path
    injector_log: Path
    capture_log: Path
    meta: Path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Record the first N seconds of Archero launch with server + Frida logs."
    )
    parser.add_argument("--device", default="127.0.0.1:26657", help="adb/frida device id/serial")
    parser.add_argument("--duration", type=int, default=60, help="seconds to record")
    parser.add_argument("--server-port", type=int, default=8443, help="host TLS port to bind")
    parser.add_argument(
        "--reverse-port",
        type=int,
        default=18443,
        help="emulator TCP port to reverse to --server-port",
    )
    parser.add_argument(
        "--reverse-plain-ports",
        default="12020",
        help="comma-separated plain ports to adb-reverse 1:1 (e.g. 12020)",
    )
    parser.add_argument(
        "--log-root",
        default="logs/sessions",
        help="directory to store session logs",
    )
    parser.add_argument(
        "--no-server",
        action="store_true",
        help="do not start/stop the server (only run injector + adb reverse)",
    )
    args = parser.parse_args()

    tag = now_tag()
    session_dir = Path(args.log_root) / f"session-{tag}"
    paths = SessionPaths(
        dir=session_dir,
        server_log=session_dir / "server.log",
        injector_log=session_dir / "injector.log",
        capture_log=session_dir / "capture.log",
        meta=session_dir / "meta.txt",
    )

    session_dir.mkdir(parents=True, exist_ok=True)
    paths.meta.write_text(
        "\n".join(
            [
                f"utc={datetime.now(timezone.utc).isoformat()}",
                f"device={args.device}",
                f"duration={args.duration}",
                f"server_port={args.server_port}",
                f"reverse_port={args.reverse_port}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    # Ensure adb reverse is set.
    # Clear common old mappings that cause unrelated localhost:443 traffic to hit the sandbox.
    run(["adb", "-s", args.device, "reverse", "--remove", "tcp:443"], check=False)
    run(["adb", "-s", args.device, "reverse", "--remove", "tcp:8443"], check=False)
    run(["adb", "-s", args.device, "reverse", "--remove", f"tcp:{args.reverse_port}"], check=False)

    run(["adb", "-s", args.device, "reverse", f"tcp:{args.reverse_port}", f"tcp:{args.server_port}"], check=False)
    for part in [p.strip() for p in str(args.reverse_plain_ports).split(",") if p.strip()]:
        try:
            port = int(part)
        except ValueError:
            continue
        run(["adb", "-s", args.device, "reverse", f"tcp:{port}", f"tcp:{port}"], check=False)

    server_proc: subprocess.Popen | None = None
    if not args.no_server:
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        env["ARCHERO_SSL_PORT"] = str(args.server_port)
        env.setdefault("ARCHERO_CERT_DIR", "/tmp/archero-certs")
        env.setdefault("ARCHERO_LOG_PEEK", "1")
        env.setdefault("ARCHERO_PLAIN_PORTS", "12020")
        server_proc = start_bg(["uv", "run", "server"], stdout_path=paths.server_log, env=env)

        # give the server a moment to bind
        time.sleep(1.0)

    # Start injector (spawn-gating + restart is what we want for "first minute").
    injector_env = os.environ.copy()
    injector_env["PYTHONUNBUFFERED"] = "1"
    injector_proc = start_bg(
        [
            sys.executable,
            "client/injector.py",
            "android",
            "--await-spawn",
            "--restart",
            "--device",
            args.device,
            "--logfile",
            str(paths.capture_log),
        ],
        stdout_path=paths.injector_log,
        env=injector_env,
    )

    try:
        time.sleep(max(1, args.duration))
    finally:
        kill_pid(injector_proc.pid, sig=signal.SIGTERM)
        try:
            injector_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            kill_pid(injector_proc.pid, sig=signal.SIGKILL)

        if server_proc is not None:
            kill_pid(server_proc.pid, sig=signal.SIGTERM)
            try:
                server_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                kill_pid(server_proc.pid, sig=signal.SIGKILL)

    print(str(paths.dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
