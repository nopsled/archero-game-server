## Archero TCP Server - Port 12020
##
## Binary protocol server for game client communication.
## Uses the protocol module for packet handling.
##
## Run: ./combined_server

import std/[net, strformat, strutils, os, nativesockets, endians]
import protocol/packet_handler

const
  TCP_PORT* = 12020
  BUFFER_SIZE = 65536


# =============================================================================
# GAME CLIENT
# =============================================================================

type
  GameClient* = ref object
    socket: Socket
    address: string
    buffer: seq[byte]
    running*: bool

  TCPServer* = ref object
    socket: Socket
    sslCtx: SslContext
    useTls: bool
    running*: bool
    port: int
    clients: seq[GameClient]

proc newGameClient(socket: Socket, address: string): GameClient =
  GameClient(socket: socket, address: address, buffer: @[], running: true)

proc toHex(data: seq[byte], maxBytes: int = 64): string =
  ## Convert bytes to hex string with truncation
  let preview = if data.len > maxBytes: data[0 ..< maxBytes] else: data
  for b in preview:
    result.add(b.toHex(2).toLowerAscii())
  if data.len > maxBytes:
    result.add("...")

proc send*(client: GameClient, data: seq[byte]) =
  ## Send data to the client
  try:
    client.socket.send(cast[string](data))

    # Verbose logging with hex preview
    if data.len >= HEADER_SIZE:
      var msgType: uint16
      littleEndian16(addr msgType, unsafeAddr data[4])
      let packetName = getPacketName(msgType)
      let hexPreview = toHex(data)
      echo fmt"[TCP][S→C] {packetName} (0x{msgType:04X}), {data.len} bytes"
      echo fmt"[TCP]      Hex: {hexPreview}"
  except:
    echo fmt"[TCP] Error sending to {client.address}: {getCurrentExceptionMsg()}"

proc processBuffer(client: GameClient) =
  ## Process complete packets from the buffer
  while client.buffer.len >= HEADER_SIZE:
    # Read packet length from header (total size including header)
    var packetLen: uint32
    littleEndian32(addr packetLen, unsafeAddr client.buffer[0])

    # Check if we have the complete packet
    if client.buffer.len.uint32 < packetLen:
      echo fmt"[TCP] Waiting for more data: have {client.buffer.len}, need {packetLen}"
      break

    # Extract complete packet
    let packetData = client.buffer[0 ..< packetLen.int]
    client.buffer = client.buffer[packetLen.int .. ^1]

    # Handle packet
    try:
      let (msgType, payload) = parsePacket(packetData)
      let packetName = getPacketName(msgType)

      # Verbose logging with hex preview
      let hexPreview = toHex(packetData)
      echo fmt"[TCP][C→S] {packetName} (0x{msgType:04X}), payload={payload.len} bytes"
      echo fmt"[TCP]      Hex: {hexPreview}"

      # Get response if any
      let response = handlePacket(msgType, payload)
      client.send(response)
    except ValueError as e:
      echo fmt"[TCP] Error handling packet: {e.msg}"

proc receiveLoop(client: GameClient) {.thread.} =
  ## Main receive loop for the client
  {.cast(gcsafe).}:
    echo fmt"[TCP] Client connected: {client.address}"
    var data = newString(BUFFER_SIZE)

    try:
      while client.running:
        let bytesRead = client.socket.recv(data, BUFFER_SIZE)
        if bytesRead <= 0:
          break

        for i in 0 ..< bytesRead:
          client.buffer.add(data[i].byte)

        client.processBuffer()
    except:
      echo fmt"[TCP] Error receiving from {client.address}: {getCurrentExceptionMsg()}"

    try:
      client.socket.close()
    except:
      discard
    echo fmt"[TCP] Connection closed: {client.address}"


# =============================================================================
# TCP SERVER
# =============================================================================

proc newTCPServer*(useTls: bool = true, certFile: string = "", keyFile: string = ""): TCPServer =
  result = TCPServer(useTls: useTls, running: false, clients: @[])

  if useTls:
    result.sslCtx = newContext(
      protSSLv23,
      verifyMode = CVerifyNone,
      certFile = certFile,
      keyFile = keyFile
    )

proc stop*(server: TCPServer) =
  ## Stop the server and close all clients
  server.running = false

  for client in server.clients:
    client.running = false
    try:
      client.socket.close()
    except:
      discard

  if server.socket != nil:
    try:
      server.socket.close()
    except:
      discard

  echo "[TCP] Server stopped"

proc run*(server: TCPServer, port: int = TCP_PORT) =
  ## Run the TCP server
  server.socket = newSocket()
  server.socket.setSockOpt(OptReuseAddr, true)
  server.socket.bindAddr(Port(port))
  server.socket.listen(10)
  server.running = true
  server.port = port

  let tlsStatus = if server.useTls: "🔒 TLS ENABLED" else: "⚠️  NO TLS"
  echo ""
  echo "╔═══════════════════════════════════════════════════════════╗"
  echo fmt"║           🎮 Archero TCP Server - Port {port}           ║"
  echo fmt"║           {tlsStatus:^41}   ║"
  echo "╚═══════════════════════════════════════════════════════════╝"
  echo ""
  let tlsLabel = if server.useTls: "Enabled" else: "Disabled"
  echo fmt"[TCP] Server listening on 0.0.0.0:{port}"
  echo fmt"[TCP] TLS: {tlsLabel}"
  echo "[TCP] Waiting for game client connections..."

  try:
    while server.running:
      var clientSocket: Socket = newSocket()
      var clientAddr = ""

      try:
        server.socket.acceptAddr(clientSocket, clientAddr)

        if server.useTls:
          try:
            server.sslCtx.wrapSocket(clientSocket)
            echo fmt"[TCP] TLS handshake completed with {clientAddr}"
          except:
            echo fmt"[TCP] TLS handshake failed with {clientAddr}: {getCurrentExceptionMsg()}"
            clientSocket.close()
            continue

        var client = newGameClient(clientSocket, clientAddr)
        server.clients.add(client)

        # Start receive thread (daemon-like — each client gets own thread)
        var clientThread: Thread[GameClient]
        createThread(clientThread, receiveLoop, client)

      except:
        echo fmt"[TCP] Accept error: {getCurrentExceptionMsg()}"
  except:
    echo "\n[TCP] Shutting down..."

  server.stop()


# Main entry point for standalone TCP server
proc main() =
  let certsDir = getAppDir() / "certs"
  let certFile = certsDir / "server.crt"
  let keyFile = certsDir / "server.key"

  let useTls = fileExists(certFile) and fileExists(keyFile)

  var server = newTCPServer(useTls, certFile, keyFile)
  server.run()

when isMainModule:
  main()
