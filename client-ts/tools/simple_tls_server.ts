import * as tls from 'tls';
import * as fs from 'fs';
import * as path from 'path';

// Load certificate and key
const options: tls.TlsOptions = {
  key: fs.readFileSync(path.join(__dirname, '../certs/key.pem')),
  cert: fs.readFileSync(path.join(__dirname, '../certs/cert.pem')),
  // Request client certificate but don't reject if missing/invalid (for debugging)
  requestCert: true, 
  rejectUnauthorized: false
};

const PORT = 12020;

const server = tls.createServer(options, (socket) => {
  console.log(`[Server] New TLS connection from ${socket.remoteAddress}:${socket.remotePort}`);

  socket.on('data', (data) => {
    console.log(`[Server] Received ${data.length} bytes:`);
    console.log(data.toString('hex'));
  });

  socket.on('end', () => {
    console.log('[Server] Connection closed by client');
  });

  socket.on('error', (err) => {
    console.error(`[Server] Socket error: ${err.message}`);
  });

  // Send a simple ServerHello/Handshake completion implies we are here.
  // We can try to send some data back if needed, e.g. a valid protocol response.
  // For now, just keep open.
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[Server] TLS Server listening on port ${PORT}`);
});

server.on('tlsClientError', (err, socket) => {
    console.error(`[Server] TLS Client Error: ${err.message}`, err);
});

server.on('error', (err) => {
    console.error(`[Server] Server Error: ${err.message}`);
});
