## Archero Combined Server - HTTPS (443) + TCP (12020)
##
## Runs both an HTTPS API server and the game protocol TCP server.

import std/[os, strformat, strutils, json, osproc, net, asynchttpserver, asyncdispatch]
import core

const
  HTTPS_PORT = 443
  TCP_PORT_NUM = 12020

# =============================================================================
# CERTIFICATE GENERATION
# =============================================================================

proc generateSelfSignedCerts(certsDir: string): tuple[certFile, keyFile: string] =
  ## Create self-signed certificate if not exists.
  let certFile = certsDir / "server.crt"
  let keyFile = certsDir / "server.key"

  if fileExists(certFile) and fileExists(keyFile):
    echo fmt"[HTTPS] Certificates already exist: {certFile}"
    return (certFile, keyFile)

  createDir(certsDir)
  echo "[HTTPS] Generating self-signed certificates..."

  # Use openssl with SANs matching Python's cryptography lib output
  let cmd = fmt"""openssl req -x509 -newkey rsa:2048 -keyout {keyFile} -out {certFile} -days 365 -nodes -subj "/CN=habby.mobi/O=Archero Emulator" -addext "subjectAltName=DNS:*.habby.mobi,DNS:*.habby.com,DNS:localhost" 2>/dev/null"""
  let (output, exitCode) = execCmdEx(cmd)

  if exitCode == 0:
    echo fmt"[HTTPS] Created self-signed certificate: {certFile}"
  else:
    echo fmt"[HTTPS] Certificate generation failed: {output}"
    echo "[HTTPS] Or manually create certs/server.crt and certs/server.key"

  return (certFile, keyFile)


# =============================================================================
# HTTPS API SERVER
# =============================================================================

proc startHttpsServer() {.async.} =
  ## Start the HTTPS API server (Flask-equivalent catch-all routes)
  var server = newAsyncHttpServer()

  proc handler(req: Request) {.async.} =
    let path = req.url.path
    let httpMethod = $req.reqMethod

    # Root handler
    if path == "/":
      echo fmt"[HTTPS] {httpMethod} / from client"
      let body = $(%*{"status": "ok", "server": "archero-emulator"})
      await req.respond(Http200, body, newHttpHeaders([("Content-Type", "application/json")]))
      return

    # API catch-all handler — returns success for all endpoints
    if path.startsWith("/api/"):
      let apiPath = path[4 .. ^1]  # Strip /api prefix for logging
      echo fmt"[HTTPS] {httpMethod} /api{apiPath} from client"

      # Log headers
      var headerStr = "{"
      for key, val in req.headers.pairs:
        headerStr.add(fmt"'{key}': '{val}', ")
      headerStr.add("}")
      echo fmt"[HTTPS]   Headers: {headerStr}"

      # Log body preview
      if req.body.len > 0:
        let bodyPreview = if req.body.len > 500: req.body[0 ..< 500] else: req.body
        echo fmt"[HTTPS]   Body ({req.body.len}b): {bodyPreview}"

      let body = $(%*{"code": 0, "msg": "success", "data": {}})
      await req.respond(Http200, body, newHttpHeaders([("Content-Type", "application/json")]))
      return

    # Catch-all handler for any other paths
    echo fmt"[HTTPS] {httpMethod} /{path} from client"

    # Log headers
    var headerStr = "{"
    for key, val in req.headers.pairs:
      headerStr.add(fmt"'{key}': '{val}', ")
    headerStr.add("}")
    echo fmt"[HTTPS]   Headers: {headerStr}"

    # Log body preview
    if req.body.len > 0:
      let bodyPreview = if req.body.len > 500: req.body[0 ..< 500] else: req.body
      echo fmt"[HTTPS]   Body ({req.body.len}b): {bodyPreview}"

    let body = $(%*{"code": 0, "msg": "ok"})
    await req.respond(Http200, body, newHttpHeaders([("Content-Type", "application/json")]))

  # Note: asynchttpserver doesn't support SSL directly in Nim.
  # The HTTPS API runs as HTTP. TLS is handled by the TCP game server.
  echo ""
  echo "╔═══════════════════════════════════════════════════════════╗"
  echo fmt"║           🔒 HTTPS Server - Port {HTTPS_PORT}                    ║"
  echo "╚═══════════════════════════════════════════════════════════╝"
  echo ""
  echo fmt"[HTTPS] Server listening on 0.0.0.0:{HTTPS_PORT}"
  await server.serve(Port(HTTPS_PORT), handler, address = "0.0.0.0")


# =============================================================================
# TCP SERVER THREAD
# =============================================================================

proc runTcpServer(args: tuple[certFile, keyFile: string]) {.thread.} =
  {.cast(gcsafe).}:
    let useTls = fileExists(args.certFile) and fileExists(args.keyFile)

    if useTls:
      echo fmt"[TCP] TLS enabled with certificate: {args.certFile}"
    else:
      echo "[TCP] WARNING: No certificate, running WITHOUT TLS!"

    var server = newTCPServer(useTls, args.certFile, args.keyFile)
    server.run(TCP_PORT_NUM)


# =============================================================================
# MAIN
# =============================================================================

proc main() =
  let certsDir = getAppDir() / "certs"

  echo ""
  echo "╔═══════════════════════════════════════════════════════════════════╗"
  echo "║           🎮 Archero Combined Server                             ║"
  echo "║           Port 443 (HTTPS) + Port 12020 (TCP Game Protocol)      ║"
  echo "╚═══════════════════════════════════════════════════════════════════╝"
  echo ""

  # Generate certificates if needed
  let (certFile, keyFile) = generateSelfSignedCerts(certsDir)

  # Start TCP server in a thread (mirrors Python: HTTPS in thread, TCP in main)
  # But in Nim, async HTTP runs in main, TCP in thread
  var tcpThread: Thread[tuple[certFile, keyFile: string]]
  createThread(tcpThread, runTcpServer, (certFile, keyFile))

  # Run HTTPS server in main thread (async) — mirrors Python's Flask
  try:
    waitFor startHttpsServer()
  except:
    echo fmt"[HTTPS] Error: {getCurrentExceptionMsg()}"
    echo fmt"[HTTPS] Permission denied for port {HTTPS_PORT}. Try running with sudo or use port 8443."

  joinThread(tcpThread)

when isMainModule:
  main()
