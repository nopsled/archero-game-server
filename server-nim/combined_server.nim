## Archero Combined Server - HTTPS (443) + TCP (12020)
##
## Runs both an HTTPS API server and the game protocol TCP server.

import std/[os, strformat, strutils, times, json, osproc, net, asynchttpserver, asyncdispatch]
import core

const
  HTTPS_PORT = 443
  TCP_PORT_NUM = 12020

# =============================================================================
# CERTIFICATE GENERATION
# =============================================================================

proc generateSelfSignedCerts(certsDir: string) =
  ## Generate self-signed certificates using OpenSSL CLI
  let certFile = certsDir / "cert.pem"
  let keyFile = certsDir / "key.pem"

  if fileExists(certFile) and fileExists(keyFile):
    echo "[HTTPS] Certificates already exist"
    return

  createDir(certsDir)
  echo "[HTTPS] Generating self-signed certificates..."

  let cmd = fmt"""openssl req -x509 -newkey rsa:2048 -keyout {keyFile} -out {certFile} -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Archero/CN=localhost" 2>/dev/null"""
  let (output, exitCode) = execCmdEx(cmd)

  if exitCode == 0:
    echo "[HTTPS] ✓ Certificates generated"
  else:
    echo fmt"[HTTPS] ✗ Certificate generation failed: {output}"

# =============================================================================
# HTTPS API SERVER
# =============================================================================

proc createJsonResponse(data: JsonNode): string =
  return $data

proc startHttpsServer(certsDir: string) {.async.} =
  ## Start the HTTPS API server
  var server = newAsyncHttpServer()

  proc handler(req: Request) {.async.} =
    let path = req.url.path
    let httpMethod = req.reqMethod

    echo fmt"[HTTPS] {httpMethod} {path}"

    # Route handling
    case path
    of "/":
      let body = createJsonResponse(%*{
        "status": "ok",
        "server": "Archero Game Server (Nim)",
        "version": "0.0.1"
      })
      await req.respond(Http200, body, newHttpHeaders([("Content-Type", "application/json")]))

    of "/api/health":
      let body = createJsonResponse(%*{
        "status": "healthy",
        "timestamp": getTime().toUnix(),
        "uptime_seconds": 0
      })
      await req.respond(Http200, body, newHttpHeaders([("Content-Type", "application/json")]))

    of "/api/version":
      let body = createJsonResponse(%*{
        "version": "0.0.1",
        "protocol_version": "12020",
        "game_version": "latest"
      })
      await req.respond(Http200, body, newHttpHeaders([("Content-Type", "application/json")]))

    of "/api/config":
      let body = createJsonResponse(%*{
        "tcp_port": TCP_PORT_NUM,
        "https_port": HTTPS_PORT,
        "tls_enabled": true
      })
      await req.respond(Http200, body, newHttpHeaders([("Content-Type", "application/json")]))

    of "/api/server/status":
      let body = createJsonResponse(%*{
        "tcp_server": "running",
        "https_server": "running",
        "connections": 0,
      })
      await req.respond(Http200, body, newHttpHeaders([("Content-Type", "application/json")]))

    of "/api/game-config/game_config.json":
      let body = createJsonResponse(%*{
        "version": 1,
        "config": {}
      })
      await req.respond(Http200, body, newHttpHeaders([("Content-Type", "application/json")]))

    of "/api/player/profile":
      let body = createJsonResponse(%*{
        "userId": 72453418394682577,
        "nickname": "",
        "level": 1,
        "coins": 199,
        "diamonds": 100
      })
      await req.respond(Http200, body, newHttpHeaders([("Content-Type", "application/json")]))

    of "/api/shop/iap":
      let body = createJsonResponse(%*{
        "products": [],
        "status": "ok"
      })
      await req.respond(Http200, body, newHttpHeaders([("Content-Type", "application/json")]))

    else:
      let body = createJsonResponse(%*{
        "error": "Not Found",
        "path": path,
        "status": 404
      })
      await req.respond(Http404, body, newHttpHeaders([("Content-Type", "application/json")]))

  # Note: asynchttpserver doesn't support SSL directly in Nim.
  # The HTTPS API runs as HTTP. TLS is handled by the TCP game server.
  echo fmt"[HTTPS] ✓ Starting HTTP API server on port {HTTPS_PORT}"
  await server.serve(Port(HTTPS_PORT), handler, address = "0.0.0.0")


# =============================================================================
# TCP SERVER THREAD
# =============================================================================

proc runTcpServer(certsDir: string) {.thread.} =
  {.cast(gcsafe).}:
    let certFile = certsDir / "cert.pem"
    let keyFile = certsDir / "key.pem"
    let useTls = fileExists(certFile) and fileExists(keyFile)

    var server = newTCPServer(useTls, certFile, keyFile)
    server.run(TCP_PORT_NUM)


# =============================================================================
# MAIN
# =============================================================================

proc main() =
  let certsDir = getAppDir() / "certs"

  echo ""
  echo "╔══════════════════════════════════════════╗"
  echo "║    Archero Combined Server (Nim)         ║"
  echo "║    HTTPS (:443) + TCP (:12020)           ║"
  echo "╚══════════════════════════════════════════╝"
  echo ""

  # Generate certificates if needed
  generateSelfSignedCerts(certsDir)

  # Start TCP server in a thread
  var tcpThread: Thread[string]
  createThread(tcpThread, runTcpServer, certsDir)

  echo fmt"[Main] TCP server thread started"

  # Run HTTPS server in main thread (async)
  echo fmt"[Main] Starting HTTPS server..."

  try:
    waitFor startHttpsServer(certsDir)
  except:
    echo fmt"[Main] HTTPS server error: {getCurrentExceptionMsg()}"
    echo "[Main] Hint: Port 443 may require root/sudo"

  joinThread(tcpThread)

when isMainModule:
  main()
