# Archero Private Server

A **minimal reverse‑engineered API stub** for the mobile game **Archero**.  
It listens on **TLS** (default `0.0.0.0:443`, configurable) and fakes enough endpoints to let a local or emulated client boot, sync and ping without touching the real Habby back–end.

> **Why?**  
> ‑ Packet analysis, modding experiments, and educational study of encrypted mobile traffic.

---

## ✨ Key Features

| Module / Concept | What It Does | File / Symbol |
|------------------|-------------|---------------|
| TLS bootstrap    | Generates an ad‑hoc self‑signed cert (defaults to `.local/certs/` if writable, else `/tmp/archero-certs/`) and wraps accepted sockets. | `generate_cert()` + `ssl.SSLContext.wrap_socket` |
| Static responses | Hard‑coded HTTP/1.1 and HTTP/2 payloads for critical Archero endpoints: `…/announcements`, `…/installations`, `…/sync`, `…/config`, `app.adjust.com/session`, Crashlytics settings, etc. | `Client.recv()` branch‑by‑substring |
| Multi‑client loop| Each incoming connection spawns a `threading.Thread` and drives a blocking `recv()` loop. | `onNewClient()` / `loop()` |
| Hot kill‑switch  | Optional: kills lingering `python` at startup (disabled by default). | `ARCHERO_PKILL_PYTHON=1` |
| Expandable game logic | Stubs for a tiny "game world" (`GameWorldManager`, `GameObject`, `PlayerObject`) to inject live objects later. | top of file |


---

## ⚡ Quick Start

```bash
# 1. Clone
git clone https://github.com/your‑user/archero‑private‑server.git
cd archero-game-server

# 2. Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# 3. Install dependencies (Python ≥ 3.13)
uv sync

# 4. Run
sudo uv run server  # binds :443

# Or run without sudo on an unprivileged port:
PYTHONUNBUFFERED=1 ARCHERO_SSL_PORT=8443 uv run server
```

The console should show:

```
[+] Server started 0.0.0.0:443. Waiting for connections...
[+] SSL handshake successful: ('127.0.0.1', 49532)
[+] Client requested: /users/<id>/announcements, response sent back to client.
```

Connect an Android emulator or MITM proxy to **`https://127.0.0.1`** and watch the fake responses flow.

---

## 📱 Android (MuMu / Emulators) Injection

This repo includes a Frida agent in `client/` that:
- Bypasses common TLS pinning (`client/android/multiple_unpinning.ts`)
- Redirects only allowlisted game hostnames to your local server (TLS `:8443`) (`client/android/socket_patcher.ts`)

### Prereqs

- Archero installed in the emulator/device (package: `com.habby.archero`)
- `adb` working (for MuMu shown as a TCP device like `127.0.0.1:26657`)
- `bun` installed (for building the agent)

### 1) Start the server (Mac host)

```bash
sudo uv run server
```

To avoid `sudo`, run the server on an unprivileged port (e.g. `8443`) and reverse the emulator’s `:18443` to it:

```bash
PYTHONUNBUFFERED=1 ARCHERO_SSL_PORT=8443 uv run server
adb -s 127.0.0.1:26657 reverse tcp:18443 tcp:8443
```

If you are also redirecting the game’s non-HTTPS port (commonly `12020`), reverse that too:

```bash
adb -s 127.0.0.1:26657 reverse tcp:12020 tcp:12020
```

If you previously used `adb reverse tcp:443 ...`, remove it to avoid capturing unrelated localhost:443 traffic:

```bash
adb -s 127.0.0.1:26657 reverse --remove tcp:443
```

If you still see `certificate unknown` TLS alerts from the emulator, you’ll need to trust the local CA:
- The server writes a CA certificate to `ARCHERO_CERT_DIR/ca.pem` (defaults to `.local/certs/` if writable, else `/tmp/archero-certs/`).
- Install that CA certificate in the emulator/device trust store (exact steps vary by emulator).

### 2) Reverse port 18443 (recommended)

Most emulators can’t reach your Mac directly, but `adb reverse` makes the emulator’s `127.0.0.1:18443`
forward to your Mac’s `127.0.0.1:8443`.

```bash
adb -s 127.0.0.1:26657 reverse tcp:18443 tcp:8443
adb -s 127.0.0.1:26657 reverse --list
```

### 3) Build the Android agent

```bash
cd client
bun install
bun run build:android
```

### 4) Run frida-server (if needed)

If attach/spawn is unreliable, running `frida-server` inside the emulator is the most stable setup.
On rooted/permissive emulators you can run it from `/data/local/tmp/frida-server`.

### 5) Inject (spawn-gating, most reliable)

Archero often kills or blocks late attach. Use spawn-gating (`-W`) and restart the app so Frida
catches it at launch:

```bash
cd ..
python3 client/injector.py android --await-spawn --restart --device 127.0.0.1:26657
```

You should see in the Frida console:
- `[Agent]: Script loaded`
- `[SocketPatcher] exports ...`
- `Installing getaddrinfo allowlist hook ...`
- `[NativeTlsLogger] Java TLS hooks installed: ...` (or native SSL exports if available)
- realtime `track(fd=...) host=...` logs and `JAVA_SSL_write/JAVA_SSL_read` payload logs for watched hostnames

### Packet capture

There are two kinds of capture:

- **TLS plaintext capture (recommended):** enabled via `NativeTlsLogger` in `client/android/index.ts`. This hooks the Java TLS stack (Conscrypt) when native `SSL_write/SSL_read` exports aren’t available and logs plaintext `JAVA_SSL_write/JAVA_SSL_read` for watched hostnames.
- **Raw socket I/O capture:** `Patcher.EnableCapture(...)` in `client/android/index.ts`. This logs libc-level `send/recv/read/write` which is often ciphertext for HTTPS.

To save the capture output to a file, pass `--logfile`:

```bash
python3 client/injector.py android --await-spawn --restart --device 127.0.0.1:26657 --logfile capture.log
```

### Record the first 60 seconds

This repo includes a small helper that runs the server + injector for a fixed duration and saves logs under `logs/sessions/`:

```bash
python3 tools/record_first_minute.py --device 127.0.0.1:26657 --duration 60
python3 tools/summarize_session.py logs/sessions/session-*/ --json
```

### Changing the redirect IP

The redirect is configured in `client/android/index.ts`. Default is `127.0.0.1` (meant for use with
`adb reverse`). If you want to route directly to a host IP instead, replace it with your Mac’s LAN IP.

---

## 🔧 Configuration

| Env / Const | Default                   | Purpose                                             |
| ----------- | ------------------------- | --------------------------------------------------- |
| `ARCHERO_SSL_PORT` | `443`               | TLS port to bind (`8443` to avoid sudo).            |
| `ARCHERO_CERT_DIR` | auto                | Override cert output dir (default auto-select).     |
| `ARCHERO_PKILL_PYTHON` | unset/`0`        | Set to `1` to run `pkill python` on startup.        |
| `ARCHERO_LOG_PEEK` | unset/`0`            | Set to `1` to log first bytes before TLS wrap.      |
| `CAPTURE_ENABLED`  | `true` (agent)        | Enables socket capture logs in `capture.log`.       |
| `ENABLE_NATIVE_TLS_BYPASS` | `true` (agent) | Best-effort native TLS verify bypass.               |
| `ENABLE_NATIVE_TLS_LOGGER` | `true` (agent) | Logs TLS plaintext for watched hostnames (best-effort). |

---

## 🛠️ Extending

1. **Add an endpoint**
   *Edit* `server/config/header.py` → append substring key and raw bytes value.
   Optionally implement a real handler under the `API` class.

2. **Inject gameplay**
   Flesh out `GameWorldManager.broadcastWorldCommand()` etc., then push JSON via `socket.send()`.

3. **Avoid `sudo`**
   Change `sslPort` to e.g. `8443` and update any client hard‑coding.

---

## 🐞 Troubleshooting

| Symptom                              | Fix                                                                          |
| ------------------------------------ | ---------------------------------------------------------------------------- |
| `ssl.SSLError: WRONG_VERSION_NUMBER` | Your client speaks TLS 1.3 only. Force TLS ≤ 1.2 or use a proper cert chain. |
| "Socket is closed" spam              | Happens when a client disconnects mid‑handshake; benign.                     |
| Port already in use                  | A previous instance stuck. `sudo pkill python` or change the port list.      |

---

## 📝 Requirements

This project uses [uv](https://docs.astral.sh/uv/) for dependency management. Dependencies are defined in `pyproject.toml`:

- **pyopenssl** – TLS certificate generation
- **msgpack** – Message serialization

> Requires **Python ≥ 3.13** and **macOS / Linux**.

---

## ⚖️ License

MIT.  Do whatever you like, **but use responsibly**—this project only emulates endpoints for **testing and research**. All trademarks and content belong to Habby Ltd.

---

## 🙌 Contributing

PRs welcome! Please open an issue first for major changes.
Focus areas: async/await refactor, proper HTTP parser, configurable JSON templates.

---

## 📣 Disclaimer

This repository is **not affiliated with Habby or Archero.**
Running it against public servers or distributing modified game clients may break the game's Terms of Service. **You are responsible for your own actions.**
