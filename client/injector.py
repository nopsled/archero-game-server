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

import frida
import psutil

# Find frida executable - check common locations
FRIDA_BIN = shutil.which("frida") or str(Path.home() / "Library/Python/3.9/bin/frida")


class Injector(ABC):
    """Base class for platform-specific Frida injectors."""

    process_name: str = "Archero"
    bundle_name: str
    script_path: Path

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
            subprocess.run(
                ["frida-kill", "-U", self.process_name],
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

        cmd = [FRIDA_BIN, "-U", "-l", str(self.script_path)]

        if spawn:
            cmd.extend(["-f", self.bundle_name])
        else:
            cmd.append(self.process_name)

        print(f"[*] Running: {' '.join(cmd)}")
        subprocess.run(cmd)

    def wait_for_process(self, timeout: int = 30) -> bool:
        """Wait for the target process to appear on the device."""
        print(f"[*] Waiting for {self.process_name}...")
        device = frida.get_usb_device(timeout=5)

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
        for proc in psutil.process_iter(["name"]):
            try:
                if self.process_name.lower() in proc.info["name"].lower():
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        return False

    def kill_process(self) -> bool:
        """Kill the process on macOS."""
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

    if args.kill:
        injector.kill_process()
        return

    if args.attach and args.platform != "macos":
        injector.inject(spawn=False)
    else:
        injector.start()


if __name__ == "__main__":
    main()
