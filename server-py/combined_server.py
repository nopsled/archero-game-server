#!/usr/bin/env python3
"""
Archero Combined Server - HTTPS (443) + TCP (12020)

Runs both an HTTPS API server and the game protocol TCP server.
"""

import ssl
import threading
import os
from pathlib import Path

# Import the TCP server
from core import TCPServer

# Try to import Flask for HTTPS API
try:
    from flask import Flask, jsonify, request
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False
    print("[HTTPS] Flask not installed. Run: uv add flask")

# Configuration
HTTPS_PORT = 443
TCP_PORT = 12020
CERT_DIR = Path(__file__).parent / "certs"


def create_self_signed_cert():
    """Create self-signed certificate if not exists."""
    cert_file = CERT_DIR / "server.crt"
    key_file = CERT_DIR / "server.key"
    
    if cert_file.exists() and key_file.exists():
        return str(cert_file), str(key_file)
    
    CERT_DIR.mkdir(exist_ok=True)
    
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        import datetime
        
        # Generate key
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        # Generate certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "habby.mobi"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Archero Emulator"),
        ])
        
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("*.habby.mobi"),
                    x509.DNSName("*.habby.com"),
                    x509.DNSName("localhost"),
                ]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        
        # Write key
        with open(key_file, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        
        # Write cert
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        print(f"[HTTPS] Created self-signed certificate: {cert_file}")
        return str(cert_file), str(key_file)
        
    except ImportError:
        print("[HTTPS] cryptography not installed. Run: uv add cryptography")
        print("[HTTPS] Or manually create certs/server.crt and certs/server.key")
        return None, None


def create_https_app():
    """Create Flask HTTPS application."""
    app = Flask(__name__)
    
    @app.route("/", methods=["GET", "POST"])
    def root():
        return jsonify({"status": "ok", "server": "archero-emulator"})
    
    @app.route("/api/<path:path>", methods=["GET", "POST", "PUT", "DELETE"])
    def api_handler(path):
        """Generic API handler - returns success for all endpoints."""
        print(f"[HTTPS] {request.method} /api/{path}")
        if request.data:
            print(f"[HTTPS] Body: {request.data[:200]}...")
        
        return jsonify({
            "code": 0,
            "msg": "success",
            "data": {}
        })
    
    @app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE"])
    def catch_all(path):
        """Catch-all handler for any other paths."""
        print(f"[HTTPS] {request.method} /{path}")
        return jsonify({"code": 0, "msg": "ok"})
    
    return app


def run_https_server():
    """Run HTTPS server."""
    if not HAS_FLASK:
        print("[HTTPS] Skipping HTTPS server (Flask not installed)")
        return
    
    cert_file, key_file = create_self_signed_cert()
    if not cert_file:
        print("[HTTPS] No certificate available, skipping HTTPS server")
        return
    
    app = create_https_app()
    
    # Create SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    
    print(f"""
╔═══════════════════════════════════════════════════════════╗
║           🔒 HTTPS Server - Port {HTTPS_PORT}                    ║
╚═══════════════════════════════════════════════════════════╝

[HTTPS] Server listening on 0.0.0.0:{HTTPS_PORT}
[HTTPS] Certificate: {cert_file}
    """)
    
    # Run in production mode (quiet)
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.WARNING)
    
    try:
        app.run(
            host="0.0.0.0",
            port=HTTPS_PORT,
            ssl_context=context,
            threaded=True,
            use_reloader=False,
        )
    except PermissionError:
        print(f"[HTTPS] Permission denied for port {HTTPS_PORT}. Try running with sudo or use port 8443.")
    except Exception as e:
        print(f"[HTTPS] Error: {e}")


def run_tcp_server():
    """Run TCP server."""
    server = TCPServer(TCP_PORT)
    server.start()


def main():
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║           🎮 Archero Combined Server                             ║
║           Port 443 (HTTPS) + Port 12020 (TCP Game Protocol)      ║
╚═══════════════════════════════════════════════════════════════════╝
    """)
    
    # Start HTTPS server in a thread
    https_thread = threading.Thread(target=run_https_server, daemon=True)
    https_thread.start()
    
    # Run TCP server in main thread (blocks)
    run_tcp_server()


if __name__ == "__main__":
    main()
