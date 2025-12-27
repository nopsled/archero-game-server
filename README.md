# Archero Private Server

A **minimal reverse‑engineered API stub** for the mobile game **Archero**.  
It listens on **`0.0.0.0:443`** (TLS) and fakes enough endpoints to let a local or emulated client boot, sync and ping without touching the real Habby back–end.

> **Why?**  
> ‑ Packet analysis, modding experiments, and educational study of encrypted mobile traffic.

---

## ✨ Key Features

| Module / Concept | What It Does | File / Symbol |
|------------------|-------------|---------------|
| TLS bootstrap    | Generates an ad‑hoc self‑signed cert (`cert.pem`, `key.pem`) at launch and wraps accepted sockets. | `generate_cert()` + `ssl.wrap_socket` |
| Static responses | Hard‑coded HTTP/1.1 and HTTP/2 payloads for critical Archero endpoints: `…/announcements`, `…/installations`, `…/sync`, `…/config`, `app.adjust.com/session`, Crashlytics settings, etc. | `Client.recv()` branch‑by‑substring |
| Multi‑client loop| Each incoming connection spawns a `threading.Thread` and drives a blocking `recv()` loop. | `onNewClient()` / `loop()` |
| Hot kill‑switch  | Kills any lingering `python` PIDs at startup so port 443 is always free. | `subprocess.run(["sudo", "pkill", "python"])` |
| Expandable game logic | Stubs for a tiny "game world" (`GameWorldManager`, `GameObject`, `PlayerObject`) to inject live objects later. | top of file |


---

## ⚡ Quick Start

```bash
# 1. Clone
git clone https://github.com/your‑user/archero‑private‑server.git
cd archero‑private‑server

# 2. Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# 3. Install dependencies (Python ≥ 3.14)
uv sync

# 4. Run (needs sudo to bind :443)
sudo uv run python Server/Core.py
```

The console should show:

```
[+] Server started 0.0.0.0:443. Waiting for connections...
[+] SSL handshake successful: ('127.0.0.1', 49532)
[+] Client requested: /users/<id>/announcements, response sent back to client.
```

Connect an Android emulator or MITM proxy to **`https://127.0.0.1`** and watch the fake responses flow.

---

## 🔧 Configuration

| Env / Const | Default                   | Purpose                                             |
| ----------- | ------------------------- | --------------------------------------------------- |
| `ports`     | `[443]`                   | TCP ports to open (additional ports commented out). |
| `sslPort`   | `443`                     | Port wrapped in TLS.                                |
| `ENDPOINTS` | `Config.Header.ENDPOINTS` | Dict of substring → body; edit to spoof new calls.  |

---

## 🛠️ Extending

1. **Add an endpoint**
   *Edit* `Config/Header.py` → append substring key and raw bytes value.
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

> Requires **Python ≥ 3.14** and **macOS / Linux**.

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
