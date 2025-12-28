#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
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


def kill_proc(proc: subprocess.Popen | None, *, sig: int = signal.SIGTERM) -> None:
    if proc is None:
        return
    try:
        proc.send_signal(sig)
    except ProcessLookupError:
        return


def wait_for_android_package(device: str, package: str, *, timeout_s: int = 20) -> bool:
    deadline = time.time() + max(1, timeout_s)
    while time.time() < deadline:
        cp = run(["adb", "-s", device, "shell", "pidof", package], check=False)
        if cp.stdout.strip():
            return True
        time.sleep(0.25)
    return False


def install_android_system_ca(*, device: str, ca_pem: Path) -> None:
    """Best-effort install of a PEM CA cert into the rooted Android system CA store."""
    if not ca_pem.exists():
        print(f"[-] CA cert not found at {ca_pem}; skipping CA install")
        return

    try:
        cp = run(
            ["openssl", "x509", "-inform", "PEM", "-subject_hash_old", "-in", str(ca_pem)],
            check=False,
        )
    except FileNotFoundError:
        print("[-] openssl not found; skipping CA install")
        return

    ca_hash = (cp.stdout.splitlines()[:1] or [""])[0].strip()
    if not ca_hash:
        print("[-] Failed to compute CA subject hash; skipping CA install")
        return

    dst = f"/system/etc/security/cacerts/{ca_hash}.0"
    print(f"[*] Installing sandbox CA into device trust store: {dst}")

    run(["adb", "-s", device, "root"], check=False)
    run(["adb", "-s", device, "remount"], check=False)
    run(["adb", "-s", device, "push", str(ca_pem), dst], check=False)
    run(["adb", "-s", device, "shell", "chmod", "644", dst], check=False)
    run(["adb", "-s", device, "shell", "chown", "0:0", dst], check=False)


@dataclass(frozen=True)
class SessionPaths:
    dir: Path
    server_log: Path
    injector_log: Path
    capture_log: Path
    meta: Path


def _pick_bun_build_script(script_path: str) -> str | None:
    name = Path(script_path).name
    mapping = {
        "agent.js": "build:android",
        "agent_12020.js": "build:android:12020",
        "agent_discover_connect.js": "build:android:discover-connect",
        "agent_force_12020.js": "build:android:force-12020",
        "agent_config.js": "build:android:config",
        "agent_dev.js": "build:android:dev",
        "agent_config_il2cpp.js": "build:android:config-il2cpp",
    }
    return mapping.get(name)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Dev runner: start local server + adb reverse + frida injector (spawn+restart).",
    )
    parser.add_argument("--device", default="127.0.0.1:26657", help="adb/frida device id/serial")
    parser.add_argument("--server-port", type=int, default=8443, help="host TLS port to bind (unprivileged)")
    parser.add_argument(
        "--reverse-port",
        type=int,
        default=18443,
        help="emulator TCP port to reverse to --server-port (used when redirecting 443)",
    )
    parser.add_argument(
        "--reverse-plain-ports",
        default="12020",
        help="comma-separated plain ports to adb-reverse 1:1 (e.g. 12020)",
    )
    parser.add_argument(
        "--script",
        default="client/android/agent_12020.js",
        help="Frida script to inject (e.g. client/android/agent_12020.js)",
    )
    parser.add_argument(
        "--config-override-dir",
        default="",
        help="Set ARCHERO_CONFIG_OVERRIDE_DIR for /data/config/*.json overrides",
    )
    parser.add_argument(
        "--config-bootstrap",
        default="",
        help="Set ARCHERO_CONFIG_BOOTSTRAP_PATH to serve /config* from a JSON file",
    )
    parser.add_argument(
        "--config-profile",
        default="",
        help="Set ARCHERO_CONFIG_PROFILE (subdir under --config-override-dir)",
    )
    parser.add_argument(
        "--enable-h2",
        action="store_true",
        help="Set ARCHERO_ENABLE_H2=1 (advertise ALPN h2)",
    )
    parser.add_argument(
        "--log-root",
        default="logs/sessions",
        help="directory to store session logs",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=0,
        help="seconds to run before stopping (0 = run until Ctrl+C)",
    )
    parser.add_argument(
        "--no-server",
        action="store_true",
        help="do not start the local server (only reverse + inject)",
    )
    parser.add_argument(
        "--attach",
        action="store_true",
        help="Attach to a running app instead of spawn-gating (more stable on some emulators)",
    )
    parser.add_argument(
        "--restart-app",
        action="store_true",
        help="adb force-stop + start the app before attaching (implies --attach)",
    )
    parser.add_argument(
        "--no-reverse",
        action="store_true",
        help="do not run adb reverse (assume you configured port forwarding yourself)",
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="do not run bun build (assume the .js script is already built)",
    )
    parser.add_argument(
        "--install-ca",
        dest="install_ca",
        action="store_true",
        default=True,
        help="install sandbox CA into Android system store (requires rooted device)",
    )
    parser.add_argument(
        "--no-install-ca",
        dest="install_ca",
        action="store_false",
        help="do not attempt to install sandbox CA into Android system store",
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
                f"server_port={args.server_port}",
                f"reverse_port={args.reverse_port}",
                f"script={args.script}",
                f"reverse_plain_ports={args.reverse_plain_ports}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    # Build agent (optional).
    if not args.no_build:
        build_script = _pick_bun_build_script(args.script)
        if build_script:
            print(f"[*] Building agent via `bun run {build_script}` ...")
            subprocess.run(["bun", "run", build_script], cwd="client", check=True)
        else:
            print(f"[*] No bun build mapping for {args.script}; skipping build (use --no-build to silence)")

    # adb reverse (optional).
    if not args.no_reverse:
        # Clear common old mappings that cause unrelated localhost:443 traffic to hit the sandbox.
        run(["adb", "-s", args.device, "reverse", "--remove", "tcp:443"], check=False)
        run(["adb", "-s", args.device, "reverse", "--remove", "tcp:8443"], check=False)
        run(
            ["adb", "-s", args.device, "reverse", "--remove", f"tcp:{args.reverse_port}"],
            check=False,
        )

        run(
            [
                "adb",
                "-s",
                args.device,
                "reverse",
                f"tcp:{args.reverse_port}",
                f"tcp:{args.server_port}",
            ],
            check=False,
        )
        for part in [p.strip() for p in str(args.reverse_plain_ports).split(",") if p.strip()]:
            try:
                port = int(part)
            except ValueError:
                continue
            run(["adb", "-s", args.device, "reverse", f"tcp:{port}", f"tcp:{port}"], check=False)

        listing = run(["adb", "-s", args.device, "reverse", "--list"], check=False)
        if listing.stdout.strip():
            print(listing.stdout.rstrip())

    # Start server (optional).
    server_proc: subprocess.Popen | None = None
    server_env: dict[str, str] | None = None
    if not args.no_server:
        server_env = os.environ.copy()
        server_env["PYTHONUNBUFFERED"] = "1"
        server_env["ARCHERO_SSL_PORT"] = str(args.server_port)
        server_env.setdefault("ARCHERO_CERT_DIR", "/tmp/archero-certs")
        server_env.setdefault("ARCHERO_LOG_PEEK", "1")
        server_env.setdefault("ARCHERO_PLAIN_PORTS", str(args.reverse_plain_ports))
        if args.config_override_dir:
            server_env["ARCHERO_CONFIG_OVERRIDE_DIR"] = args.config_override_dir
        if args.config_profile:
            server_env["ARCHERO_CONFIG_PROFILE"] = args.config_profile
        if args.config_bootstrap:
            server_env["ARCHERO_CONFIG_BOOTSTRAP_PATH"] = args.config_bootstrap
        if args.enable_h2:
            server_env["ARCHERO_ENABLE_H2"] = "1"
        print(f"[*] Starting server on 0.0.0.0:{args.server_port} ...")
        server_proc = start_bg(
            ["uv", "run", "server"],
            stdout_path=paths.server_log,
            env=server_env,
        )
        time.sleep(1.0)

    if args.install_ca and server_env is not None:
        cert_dir = Path(server_env.get("ARCHERO_CERT_DIR", "/tmp/archero-certs"))
        install_android_system_ca(device=args.device, ca_pem=cert_dir / "ca.pem")

    # Start injector (spawn-gating + restart).
    injector_env = os.environ.copy()
    injector_env["PYTHONUNBUFFERED"] = "1"
    print(f"[*] Starting injector + launching client (logs: {paths.dir}) ...")
    attach_mode = bool(args.attach or args.restart_app)
    if attach_mode and args.restart_app:
        run(
            ["adb", "-s", args.device, "shell", "am", "force-stop", "com.habby.archero"],
            check=False,
        )
        run(
            [
                "adb",
                "-s",
                args.device,
                "shell",
                "monkey",
                "-p",
                "com.habby.archero",
                "-c",
                "android.intent.category.LAUNCHER",
                "1",
            ],
            check=False,
        )
        if not wait_for_android_package(args.device, "com.habby.archero", timeout_s=25):
            print("[-] App did not start (pidof com.habby.archero timed out); injector may fail to attach")
        else:
            time.sleep(0.5)

    injector_cmd = [sys.executable, "client/injector.py", "android"]
    if attach_mode:
        injector_cmd += ["--attach"]
    else:
        injector_cmd += ["--await-spawn", "--restart"]
    injector_cmd += [
        "--device",
        args.device,
        "--script",
        str(Path(args.script)),
        "--logfile",
        str(paths.capture_log),
    ]

    injector_proc = start_bg(injector_cmd, stdout_path=paths.injector_log, env=injector_env)

    try:
        if args.duration > 0:
            deadline = time.time() + max(1, args.duration)
            while time.time() < deadline:
                rc = injector_proc.poll()
                if rc is not None:
                    return int(rc)
                time.sleep(0.25)
            return 0

        # Block until injector exits; Ctrl+C to stop both.
        while True:
            rc = injector_proc.poll()
            if rc is not None:
                return int(rc)
            time.sleep(0.25)
    except KeyboardInterrupt:
        return 0
    finally:
        kill_proc(injector_proc, sig=signal.SIGTERM)
        try:
            injector_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            kill_proc(injector_proc, sig=signal.SIGKILL)

        kill_proc(server_proc, sig=signal.SIGTERM)
        if server_proc is not None:
            try:
                server_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                kill_proc(server_proc, sig=signal.SIGKILL)


if __name__ == "__main__":
    raise SystemExit(main())
