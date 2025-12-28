#!/usr/bin/env python3
"""Frida script injector for Archero on multiple platforms."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
from abc import ABC, abstractmethod
from pathlib import Path

try:
    import frida  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    frida = None

try:
    import psutil  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    psutil = None

# Find frida executable - check common locations
FRIDA_BIN = shutil.which("frida") or str(Path.home() / "Library/Python/3.9/bin/frida")


class Injector(ABC):
    """Base class for platform-specific Frida injectors."""

    process_name: str = "Archero"
    bundle_name: str
    script_path: Path
    device_id: str | None = None
    logfile: Path | None = None

    def __init__(self, script_path: Path | None = None):
        if script_path:
            self.script_path = script_path

    @abstractmethod
    def start(self) -> None:
        """Start the injection process."""
        pass

    def kill_process(self) -> bool:
        """Kill the target process."""
        try:
            cmd = ["frida-kill"]
            if self.device_id:
                cmd.extend(["-D", self.device_id])
            else:
                cmd.append("-U")
            cmd.append(self.process_name)
            subprocess.run(
                cmd,
                check=True,
                capture_output=True,
            )
            print(f"[+] {self.process_name} killed")
            return True
        except subprocess.CalledProcessError as e:
            print(f"[-] Failed to kill {self.process_name}: {e}")
            return False

    def inject(self, spawn: bool = False) -> None:
        """Inject the Frida script into the target process."""
        if not self.script_path.exists():
            print(f"[-] Script not found: {self.script_path}")
            sys.exit(1)

        cmd = [FRIDA_BIN]
        if self.device_id:
            cmd.extend(["-D", self.device_id])
        else:
            cmd.append("-U")
        cmd.extend(["-l", str(self.script_path)])
        if self.logfile:
            cmd.extend(["-o", str(self.logfile)])

        if spawn:
            cmd.extend(["-f", self.bundle_name])
        else:
            # Prefer attaching by identifier (e.g. Android package name), as the process name
            # can vary (some emulators show the app label like "Archero").
            if getattr(self, "bundle_name", None):
                cmd.extend(["-N", self.bundle_name])
            else:
                cmd.extend(["-n", self.process_name])

        print(f"[*] Running: {' '.join(cmd)}")
        try:
            subprocess.run(cmd, check=False)
        except FileNotFoundError:
            print(f"[-] Frida CLI not found: {FRIDA_BIN}")
            sys.exit(1)

    def await_spawn(self) -> None:
        """Wait for a spawn matching the bundle id and inject."""
        if not self.script_path.exists():
            print(f"[-] Script not found: {self.script_path}")
            sys.exit(1)

        if not getattr(self, "bundle_name", None):
            print("[-] await_spawn requires bundle_name")
            sys.exit(1)

        cmd = [FRIDA_BIN]
        if self.device_id:
            cmd.extend(["-D", self.device_id])
        else:
            cmd.append("-U")
        cmd.extend(["-W", self.bundle_name, "-l", str(self.script_path)])
        if self.logfile:
            cmd.extend(["-o", str(self.logfile)])

        print(f"[*] Running: {' '.join(cmd)}")
        subprocess.run(cmd, check=False)

    def wait_for_process(self, timeout: int = 30) -> bool:
        """Wait for the target process to appear on the device."""
        if frida is None:
            print("[-] Python module 'frida' is not installed; cannot use wait_for_process()")
            return False
        print(f"[*] Waiting for {self.process_name}...")
        device = (
            frida.get_device(self.device_id, timeout=5)
            if self.device_id
            else frida.get_usb_device(timeout=5)
        )

        for _ in range(timeout):
            processes = device.enumerate_processes()
            for process in processes:
                if process.name == self.process_name:
                    print(f"[+] {self.process_name} found (PID: {process.pid})")
                    return True
            time.sleep(1)

        print(f"[-] {self.process_name} not found after {timeout}s")
        return False


class AndroidInjector(Injector):
    """Frida injector for Android devices."""

    bundle_name = "com.habby.archero"
    script_path = Path("client/android/agent.js")

    def start(self) -> None:
        """Spawn the app and inject the script."""
        self.inject(spawn=True)

    def restart_app(self) -> None:
        """Force-stop and start the app using adb."""
        if not self.device_id:
            raise RuntimeError("--restart requires --device (adb serial)")
        subprocess.run(
            ["adb", "-s", self.device_id, "shell", "am", "force-stop", self.bundle_name],
            check=False,
        )
        subprocess.run(
            [
                "adb",
                "-s",
                self.device_id,
                "shell",
                "monkey",
                "-p",
                self.bundle_name,
                "-c",
                "android.intent.category.LAUNCHER",
                "1",
            ],
            check=False,
        )

    def await_spawn_with_restart(self) -> None:
        """Start waiting for spawn, then restart the app so Frida can catch it."""
        if not self.script_path.exists():
            print(f"[-] Script not found: {self.script_path}")
            sys.exit(1)
        if not self.device_id:
            print("[-] --restart requires --device (adb serial)")
            sys.exit(1)

        cmd = [FRIDA_BIN, "-D", self.device_id, "-W", self.bundle_name, "-l", str(self.script_path)]
        if self.logfile:
            cmd.extend(["-o", str(self.logfile)])
        print(f"[*] Running: {' '.join(cmd)}")

        process = subprocess.Popen(cmd)
        time.sleep(1)
        self.restart_app()
        process.wait()


class IOSInjector(Injector):
    """Frida injector for iOS devices."""

    bundle_name = "com.habby.archero.3Z58P8MNX4"
    script_path = Path("client/ios/agent.js")

    def start(self) -> None:
        """Spawn the app and inject the script."""
        self.inject(spawn=True)


class MacOSInjector(Injector):
    """Frida injector for macOS (PlayCover)."""

    bundle_name = "io.playcover.PlayCover"
    script_path = Path("agent.js")

    def __init__(self, script_path: Path | None = None):
        super().__init__(script_path)
        self.app_path = (
            Path.home() / "Library/Containers/io.playcover.PlayCover/Archero.app"
        )

    def is_running(self) -> bool:
        """Check if the process is running."""
        if psutil is None:
            raise RuntimeError("psutil is required for macOS injector")
        for proc in psutil.process_iter(["name"]):
            try:
                if self.process_name.lower() in proc.info["name"].lower():
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        return False

    def kill_process(self) -> bool:
        """Kill the process on macOS."""
        if psutil is None:
            raise RuntimeError("psutil is required for macOS injector")
        for proc in psutil.process_iter(["name"]):
            try:
                if self.process_name.lower() in proc.info["name"].lower():
                    proc.kill()
                    print(f"[+] {self.process_name} killed")
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        return False

    def start_app(self) -> None:
        """Start the app using open command."""
        subprocess.run(["open", str(self.app_path)], check=True)
        print(f"[+] {self.process_name} started")

    def start(self) -> None:
        """Kill, restart, and inject into the app."""
        if self.is_running():
            self.kill_process()

        self.start_app()

        # Wait for app to start
        for _ in range(10):
            if self.is_running():
                break
            time.sleep(0.5)

        subprocess.run(["frida", "-l", str(self.script_path), self.process_name])


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Inject Frida scripts into Archero",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s android          Spawn and inject on Android
  %(prog)s ios              Spawn and inject on iOS  
  %(prog)s macos            Kill, restart, and inject on macOS
  %(prog)s android --attach Attach to running process (don't spawn)
        """,
    )

    parser.add_argument(
        "platform",
        choices=["android", "ios", "macos"],
        help="Target platform",
    )
    parser.add_argument(
        "--attach",
        action="store_true",
        help="Attach to running process instead of spawning",
    )
    parser.add_argument(
        "--script",
        type=Path,
        help="Custom script path (overrides default)",
    )
    parser.add_argument(
        "--device",
        dest="device_id",
        help="Frida device id (passed to `frida -D ...`); defaults to USB (`-U`)",
    )
    parser.add_argument(
        "--logfile",
        type=Path,
        help="Write Frida output (including packet logs) to a file",
    )
    parser.add_argument(
        "--await-spawn",
        action="store_true",
        help="Wait for a spawn matching the app identifier and inject (uses `frida -W`)",
    )
    parser.add_argument(
        "--restart",
        action="store_true",
        help="Android only: force-stop + start the app via adb before awaiting spawn",
    )
    parser.add_argument(
        "--kill",
        action="store_true",
        help="Kill the process and exit",
    )

    args = parser.parse_args()

    injectors = {
        "android": AndroidInjector,
        "ios": IOSInjector,
        "macos": MacOSInjector,
    }

    injector = injectors[args.platform](args.script)
    injector.device_id = args.device_id
    injector.logfile = args.logfile

    if args.kill:
        injector.kill_process()
        return

    if args.await_spawn:
        if args.restart and args.platform == "android":
            injector.await_spawn_with_restart()
        else:
            injector.await_spawn()
        return

    if args.attach and args.platform != "macos":
        injector.inject(spawn=False)
    else:
        injector.start()


if __name__ == "__main__":
    main()
