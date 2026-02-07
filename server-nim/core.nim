## Archero TCP Server - Port 12020
##
## Binary protocol server for game client communication.
## Uses the protocol module for packet handling.

import std/[net, strformat, os, nativesockets]
import protocol/packet_handler
import protocol/packet

const
  TCP_PORT* = 12020
  BUFFER_SIZE = 65536

type
  GameClient* = object
    socket: Socket
    address: string
    buffer: seq[byte]
    connected: bool

  TCPServer* = object
    socket: Socket
    useTls: bool
    sslCtx: SslContext
    running: bool

proc newGameClient(socket: Socket, address: string): GameClient =
  GameClient(socket: socket, address: address, buffer: @[], connected: true)

proc processPackets(client: var GameClient) =
  ## Process complete packets from the buffer
  while client.buffer.len >= 6:  # 4 bytes length + 2 bytes msg type
    # Read total length from first 4 bytes
    var totalLen: uint32
    copyMem(addr totalLen, addr client.buffer[0], 4)

    let packetLen = 4 + totalLen.int  # length prefix + payload
    if client.buffer.len < packetLen:
      break  # Wait for more data

    # Extract and process the packet
    let packetData = client.buffer[0 ..< packetLen]
    client.buffer = client.buffer[packetLen .. ^1]

    try:
      let (pkt, _) = Packet.fromBytes(packetData)
      let response = handlePacket(pkt.msgType, pkt.payload)
      client.socket.send(cast[string](response))
      echo fmt"[TCP] >> Response sent ({response.len}B)"
    except ValueError as e:
      echo fmt"[TCP] Error processing packet: {e.msg}"

proc handleClient(client: var GameClient) =
  ## Handle a connected client
  echo fmt"[TCP] Client connected: {client.address}"
  var data = newString(BUFFER_SIZE)

  while client.connected:
    try:
      let bytesRead = client.socket.recv(data, BUFFER_SIZE)
      if bytesRead <= 0:
        echo fmt"[TCP] Client disconnected: {client.address}"
        client.connected = false
        break

      # Add received data to buffer
      for i in 0 ..< bytesRead:
        client.buffer.add(data[i].byte)

      echo fmt"[TCP] Received {bytesRead}B from {client.address} (buffer: {client.buffer.len}B)"
      client.processPackets()
    except:
      echo fmt"[TCP] Error with client {client.address}: {getCurrentExceptionMsg()}"
      client.connected = false
      break

  try:
    client.socket.close()
  except:
    discard

proc newTCPServer*(useTls: bool = true, certFile: string = "", keyFile: string = ""): TCPServer =
  result.useTls = useTls
  result.running = false

  if useTls:
    result.sslCtx = newContext(
      protSSLv23,
      verifyMode = CVerifyNone,
      certFile = certFile,
      keyFile = keyFile
    )

proc run*(server: var TCPServer, port: int = TCP_PORT) =
  ## Run the TCP server
  server.socket = newSocket()
  server.socket.setSockOpt(OptReuseAddr, true)
  server.socket.bindAddr(Port(port))
  server.socket.listen()
  server.running = true

  echo fmt"[TCP] ✓ Server listening on port {port}" & (if server.useTls: " (TLS)" else: "")

  while server.running:
    var clientSocket: Socket = newSocket()
    var clientAddr = ""

    try:
      server.socket.acceptAddr(clientSocket, clientAddr)

      if server.useTls:
        try:
          server.sslCtx.wrapSocket(clientSocket)
        except:
          echo fmt"[TCP] TLS handshake failed for {clientAddr}: {getCurrentExceptionMsg()}"
          clientSocket.close()
          continue

      var client = newGameClient(clientSocket, clientAddr)
      # Handle client in current thread (blocking)
      # For production, spawn threads
      handleClient(client)
    except:
      echo fmt"[TCP] Accept error: {getCurrentExceptionMsg()}"

proc stop*(server: var TCPServer) =
  server.running = false
  try:
    server.socket.close()
  except:
    discard

# Main entry point for standalone TCP server
proc main() =
  let certsDir = getAppDir() / "certs"
  let certFile = certsDir / "cert.pem"
  let keyFile = certsDir / "key.pem"

  let useTls = fileExists(certFile) and fileExists(keyFile)

  echo "╔══════════════════════════════════════╗"
  echo "║    Archero TCP Server (Nim)          ║"
  echo "╚══════════════════════════════════════╝"
  echo ""

  var server = newTCPServer(useTls, certFile, keyFile)
  server.run()

when isMainModule:
  main()
