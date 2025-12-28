#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


TS_RE = re.compile(r"\[(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)\]\s+(?P<rest>.*)")


@dataclass(frozen=True)
class Event:
    ts: str
    source: str
    kind: str
    detail: str


def parse_capture_line(line: str) -> Event | None:
    m = TS_RE.search(line)
    if not m:
        return None
    ts = m.group("ts")
    rest = m.group("rest").strip()
    if rest.startswith("connect("):
        return Event(ts=ts, source="agent", kind="connect", detail=rest)
    if rest.startswith(("send(", "recv(", "write(", "read(", "sendto(", "recvfrom(", "sendmsg(", "recvmsg(")):
        return Event(ts=ts, source="agent", kind="io", detail=rest)
    if rest.startswith("sys_"):
        return Event(ts=ts, source="agent", kind="syscall", detail=rest)
    return Event(ts=ts, source="agent", kind="log", detail=rest)


def parse_server_line(line: str) -> Event | None:
    # server log doesn't include ISO timestamps; keep it separate
    if "SSL handshake successful" in line:
        return Event(ts="", source="server", kind="tls_ok", detail=line.strip())
    if "SSL handshake failed" in line:
        return Event(ts="", source="server", kind="tls_fail", detail=line.strip())
    if "Pre-TLS peek" in line:
        return Event(ts="", source="server", kind="tls_peek", detail=line.strip())
    if "New game client connected" in line:
        return Event(ts="", source="server", kind="client", detail=line.strip())
    return None


def summarize_capture(capture_path: Path) -> dict:
    connects = 0
    patched_connects = 0
    connect_errno = Counter()
    io_lines = 0

    endpoints = Counter()
    ports = Counter()

    for raw in capture_path.read_text(encoding="utf-8", errors="replace").splitlines():
        evt = parse_capture_line(raw)
        if evt is None:
            continue
        if evt.kind == "connect":
            connects += 1
            if "(patched)" in evt.detail:
                patched_connects += 1
            m = re.search(r":(?P<port>\\d+)", evt.detail)
            if m:
                ports[m.group("port")] += 1
            m = re.search(r"\\((?P<errno>E[A-Z0-9_]+)\\)", evt.detail)
            if m:
                connect_errno[m.group("errno")] += 1
        elif evt.kind in ("io", "syscall"):
            io_lines += 1

        # best-effort host extraction for connect lines
        if "->" in evt.detail:
            # connect(fd=..) A:B -> C:D (patched)
            parts = evt.detail.split("->", 1)
            if len(parts) == 2:
                endpoints[parts[0].strip()] += 1

    return {
        "connects": connects,
        "patched_connects": patched_connects,
        "connect_errno_top": connect_errno.most_common(10),
        "ports_top": ports.most_common(10),
        "io_lines": io_lines,
    }


def summarize_server(server_path: Path) -> dict:
    tls_ok = 0
    tls_fail = Counter()
    peeks = 0

    for line in server_path.read_text(encoding="utf-8", errors="replace").splitlines():
        evt = parse_server_line(line)
        if evt is None:
            continue
        if evt.kind == "tls_ok":
            tls_ok += 1
        elif evt.kind == "tls_fail":
            m = re.search(r"\\] (?P<reason>.+)$", evt.detail)
            if m:
                tls_fail[m.group("reason")] += 1
            else:
                tls_fail[evt.detail] += 1
        elif evt.kind == "tls_peek":
            peeks += 1

    return {"tls_ok": tls_ok, "tls_fail_top": tls_fail.most_common(10), "tls_peeks": peeks}


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize a recorded session directory.")
    parser.add_argument("session_dir", help="directory produced by tools/record_first_minute.py")
    parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    args = parser.parse_args()

    session_dir = Path(args.session_dir)
    capture = session_dir / "capture.log"
    server = session_dir / "server.log"
    injector = session_dir / "injector.log"

    out = {
        "session_dir": str(session_dir),
        "capture": str(capture) if capture.exists() else None,
        "server": str(server) if server.exists() else None,
        "injector": str(injector) if injector.exists() else None,
        "capture_summary": summarize_capture(capture) if capture.exists() else None,
        "server_summary": summarize_server(server) if server.exists() else None,
    }

    if args.json:
        print(json.dumps(out, indent=2, sort_keys=True))
        return 0

    print(f"session: {out['session_dir']}")
    if out["capture_summary"]:
        cs = out["capture_summary"]
        print(f"agent: connects={cs['connects']} patched={cs['patched_connects']} io_lines={cs['io_lines']}")
        if cs["connect_errno_top"]:
            print(f"agent: connect errno top={cs['connect_errno_top'][:5]}")
        if cs["ports_top"]:
            print(f"agent: ports top={cs['ports_top'][:5]}")
    if out["server_summary"]:
        ss = out["server_summary"]
        print(f"server: tls_ok={ss['tls_ok']} tls_peeks={ss['tls_peeks']}")
        if ss["tls_fail_top"]:
            print(f"server: tls_fail top={ss['tls_fail_top'][:5]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
