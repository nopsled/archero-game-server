/// <reference path="../../frida.d.ts" />
import "frida-il2cpp-bridge";
import { NativeTlsBypass } from "../patchers/native_tls_bypass";


/**
 * Raw Socket Logger for Port 12020
 * 
 * Focuses strictly on capturing raw libc socket operations for port 12020
 * to understand the protocol structure.
 */

// Track file descriptors connected to interesting ports
const interestingFds = new Map<number, { ip: string; port: number }>();
const INTERESTING_PORTS = [12020];

// Helper for timestamp
function ts(): string {
    const now = new Date();
    return `[${now.toISOString().split('T')[1].slice(0, -1)}]`;
}

// Helper to check if we should log this fd
function shouldLog(fd: number): boolean {
    return interestingFds.has(fd);
}

// Helper for hex dump - REMOVED (using improved version below)

function hookLibc() {
    console.log("[*] Hooking libc...");
    
    const libc = Process.getModuleByName("libc.so");
    console.log(`[*] libc.so found at ${libc.base}`);

    // --- getaddrinfo ---
    const getaddrinfoPtr = libc.findExportByName("getaddrinfo");
    if (getaddrinfoPtr) {
        Interceptor.attach(getaddrinfoPtr, {
            onEnter(args) {
                this.node = args[0].readCString();
                this.service = args[1].readCString();
                // console.log(`${ts()} [getaddrinfo] node=${this.node} service=${this.service}`); 
                // Log all for now to see what's happening
            },
            onLeave(retval) {
                // If it resolves, we might want to log.
                // But mainly we want to see if it's called for 12020 related domains.
                 if (this.node) console.log(`${ts()} [getaddrinfo] Resolving ${this.node} for service ${this.service} -> ret=${retval}`);
            }
        });
        console.log(" [+] getaddrinfo hooked");
    }

    // --- connect ---
    const connectPtr = libc.findExportByName("connect");
    if (connectPtr) {
        Interceptor.attach(connectPtr, {
            onEnter(args) {
                this.fd = args[0].toInt32();
                const sockaddr = args[1];
                this.port = 0;
                this.ip = "";
                
                try {
                    const family = sockaddr.readU16();
                    if (family === 2) { // AF_INET
                        this.port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
                        // this.ip is just for logging original
                        this.ip = `${sockaddr.add(4).readU8()}.${sockaddr.add(5).readU8()}.${sockaddr.add(6).readU8()}.${sockaddr.add(7).readU8()}`;
                        
                        if (INTERESTING_PORTS.includes(this.port)) {
                            console.log(`${ts()} [MATCH] ⏳ Attempting connection to ${this.ip}:${this.port} (fd=${this.fd})...`);
                            
                            // REDIRECT to 10.0.2.2 (Host Loopback)
                            // 10.0.2.2 -> 0A 00 02 02
                            // sock_addr_in.sin_addr is at offset 4
                            sockaddr.add(4).writeU8(10);
                            sockaddr.add(5).writeU8(0);
                            sockaddr.add(6).writeU8(2);
                            sockaddr.add(7).writeU8(2);
                            console.log(`${ts()} [REDIRECT] >>> Redirected fd=${this.fd} to 10.0.2.2:${this.port}`);
                        }
                    }
                } catch (e) {}
            },
            onLeave(retval) {
                const ret = retval.toInt32();
                if (INTERESTING_PORTS.includes(this.port)) {
                    if (ret === 0) {
                        console.log(`${ts()} [MATCH] ✅ Connected to ${this.ip}:${this.port} (fd=${this.fd})`);
                        interestingFds.set(this.fd, { ip: this.ip, port: this.port });
                    } else {
                        console.log(`${ts()} [MATCH] ❌ Connect failed to ${this.ip}:${this.port} (fd=${this.fd}) ret=${ret}`);
                        // Even if EINPROGRESS (-1), we might want to track it if we hook select/poll, 
                        // but for now assume failed if not 0.
                        // Actually, EINPROGRESS is -1 with errno=115. We can't read errno easily without calling __errno().
                        // Let's track it anyway just to see if data flows later?
                        if (ret === -1) {
                             console.log("    (Likely EINPROGRESS, tracking anyway)");
                             interestingFds.set(this.fd, { ip: this.ip, port: this.port });
                        }
                    }
                }
            }
        });
        console.log(" [+] connect hooked");
    } else {
        console.log(" [-] connect NOT found");
    }

    // --- send / sendto ---
    const hookSend = (name: string) => {
        const ptr = libc.findExportByName(name);
        if (ptr) {
            Interceptor.attach(ptr, {
                onEnter(args) {
                    const fd = args[0].toInt32();
                    if (shouldLog(fd)) {
                        const len = args[2].toInt32();
                        const data = args[1];
                        console.log(`${ts()} [${name}] fd=${fd} len=${len}`);
                        console.log(hex(data, len));
                    }
                }
            });
            console.log(` [+] ${name} hooked`);
        } else {
            console.log(` [-] ${name} NOT found`);
        }
    }
    hookSend("send");
    hookSend("sendto"); // Usually udp, but sometimes used for tcp

    // --- recv / recvfrom ---
    const hookRecv = (name: string) => {
        const ptr = libc.findExportByName(name);
        if (ptr) {
            Interceptor.attach(ptr, {
                onEnter(args) {
                    this.fd = args[0].toInt32();
                    this.buf = args[1];
                    this.len = args[2].toInt32();
                },
                onLeave(retval) {
                    if (shouldLog(this.fd)) {
                        const ret = retval.toInt32();
                        if (ret > 0) {
                            console.log(`${ts()} [${name}] fd=${this.fd} len=${ret}`);
                            console.log(hex(this.buf, ret));
                        }
                    }
                }
            });
            console.log(` [+] ${name} hooked`);
        } else {
            console.log(` [-] ${name} NOT found`);
        }
    }
    hookRecv("recv");
    hookRecv("recvfrom");

    // --- read / write ---
    const hookReadWrite = (name: string, isRead: boolean) => {
        const ptr = libc.findExportByName(name);
        if (ptr) {
            Interceptor.attach(ptr, {
                onEnter(args) {
                    this.fd = args[0].toInt32();
                    this.buf = args[1];
                    // len is arg 2
                    if (!isRead && shouldLog(this.fd)) {
                         this.len = args[2].toInt32();
                         const data = this.buf;
                         console.log(`${ts()} [${name}] fd=${this.fd} len=${this.len}`);
                         console.log(hex(data, this.len));
                    }
                },
                onLeave(retval) {
                    if (isRead && shouldLog(this.fd)) {
                        const ret = retval.toInt32();
                        if (ret > 0) {
                            console.log(`${ts()} [${name}] fd=${this.fd} len=${ret}`);
                            console.log(hex(this.buf, ret));
                        }
                    }
                }
            });
            console.log(` [+] ${name} hooked`);
        }
    }
    hookReadWrite("read", true);
    hookReadWrite("write", false);

    // --- writev ---
    const writevPtr = libc.findExportByName("writev");
    if (writevPtr) {
        Interceptor.attach(writevPtr, {
            onEnter(args) {
                const fd = args[0].toInt32();
                if (shouldLog(fd)) {
                    const iov = args[1];
                    const iovcnt = args[2].toInt32();
                    console.log(`${ts()} [writev] fd=${fd} iovcnt=${iovcnt}`);
                    for (let i = 0; i < iovcnt; i++) {
                        const ptr = iov.add(i * 16); // sizeof(iovec) = 16 (64-bit) or 8 (32-bit). Assuming 64-bit for now as it's an emulator/modern device.
                        // Actually, let's verify pointer size. Process.pointerSize
                        const ptrSize = Process.pointerSize;
                        const iov_base = ptr.readPointer();
                        const iov_len = ptr.add(ptrSize).readU32(); // size_t
                        console.log(`    iov[${i}] len=${iov_len}`);
                        console.log(hex(iov_base, iov_len));
                    }
                }
            }
        });
        console.log(" [+] writev hooked");
    }

    // --- close ---
    const closePtr = libc.findExportByName("close");
    if (closePtr) {
        Interceptor.attach(closePtr, {
            onEnter(args) {
                const fd = args[0].toInt32();
                if (interestingFds.has(fd)) {
                    console.log(`${ts()} [close] fd=${fd} (Closing connection to ${interestingFds.get(fd)?.port})`);
                    interestingFds.delete(fd);
                }
            }
        });
    }

    // --- sendmsg (decoded) ---
    const sendmsgPtr = libc.findExportByName("sendmsg");
    if (sendmsgPtr) {
         Interceptor.attach(sendmsgPtr, {
             onEnter(args) {
                 const fd = args[0].toInt32();
                 if (shouldLog(fd)) {
                     const msg = args[1]; // struct msghdr *
                     // struct msghdr layout (approx for 64-bit Android):
                     // 0x00: msg_name (void*)
                     // 0x08: msg_namelen (socklen_t)
                     // 0x10: msg_iov (struct iovec*)
                     // 0x18: msg_iovlen (size_t) ...
                     
                     const msg_iov = msg.add(16).readPointer(); // offset 0x10
                     const msg_iovlen = msg.add(24).readU32();  // offset 0x18 (or readU64? size_t is 64-bit)
                     // Let's assume 64-bit size_t
                     // Actually, parsing struct layout can be tricky. Let's try reading as ptr then cast.
                     
                     // Safer way for iov count:
                     const ptrSize = Process.pointerSize;
                     const iovPtr = msg.add(2 * ptrSize); // skip name, namelen (namelen is 4 bytes but aligned padding?)
                     // wait, struct msghdr:
                     // void *msg_name; (8)
                     // socklen_t msg_namelen; (4)
                     // PAD (4)
                     // struct iovec *msg_iov; (8) -> offset 16
                     // size_t msg_iovlen; (8) -> offset 24
                     
                     const iov = msg.add(16).readPointer();
                     const iovcnt = msg.add(24).readU64().toNumber(); // size_t

                     console.log(`${ts()} [sendmsg] fd=${fd} iovcnt=${iovcnt}`);
                     for (let i = 0; i < Math.min(iovcnt, 8); i++) {
                         const iovStruct = iov.add(i * 16); // 16 bytes per iovec
                         const base = iovStruct.readPointer();
                         const len = iovStruct.add(8).readU64().toNumber();
                         console.log(`    iov[${i}] len=${len}`);
                         console.log(hex(base, len));
                     }
                 }
             }
         });
         console.log(" [+] sendmsg hooked");
    }
    
    // recvmsg is harder to hook on enter (buffer empty), need hook onLeave + struct parsing
    // For now we skip detailed recvmsg decoding unless needed.

    console.log("[*] Hooks installed. Waiting for traffic...");

    // Enumerate Crypto Modules
    console.log("[*] Checking for interesting loaded modules...");
    Process.enumerateModules().forEach(m => {
        const lower = m.name.toLowerCase();
        if (lower.includes("ssl") || lower.includes("crypto") || lower.includes("tls") || lower.includes("mbed")) {
            console.log(`    Loaded: ${m.name} @ ${m.base} (${m.path})`);
        }
    });
}

// Improved hex dump with protocol hints
function hex(data: NativePointer, len: number): string {
    try {
        const buffer = data.readByteArray(Math.min(len, 256));
        if (!buffer) return "[read error]";
        
        const bytes = new Uint8Array(buffer);
        let hexStr = "";
        let asciiStr = "";
        let protocol = "";

        // Simple Protocol Detection
        if (len >= 3) {
            if (bytes[0] === 0x16 && bytes[1] === 0x03) protocol = " [TLS Handshake]";
            else if (bytes[0] === 0x17 && bytes[1] === 0x03) protocol = " [TLS App Data]";
            else if (bytes[0] === 0x14 && bytes[1] === 0x03) protocol = " [TLS ChangeCipher]";
            else if (bytes[0] === 0x15 && bytes[1] === 0x03) protocol = " [TLS Alert]";
            else if (bytes[0] === 0x47 && bytes[1] === 0x45 && bytes[2] === 0x54) protocol = " [HTTP GET]";
            else if (bytes[0] === 0x50 && bytes[1] === 0x4F && bytes[2] === 0x53) protocol = " [HTTP POST]";
            else if (bytes[0] === 0x48 && bytes[1] === 0x54 && bytes[2] === 0x54) protocol = " [HTTP/1.1]";
        }

        for (let i = 0; i < bytes.length; i++) {
            hexStr += bytes[i].toString(16).padStart(2, '0') + " ";
            asciiStr += (bytes[i] >= 32 && bytes[i] <= 126) ? String.fromCharCode(bytes[i]) : ".";
        }
        
        if (len > 256) hexStr += "...";
        
        return `Protocol:${protocol}\nHEX: ${hexStr.trim()}\nASC: ${asciiStr}`;
    } catch (e) {
        return `[error: ${e}]`;
    }
}


// Refactored to separate functions
function hookSystemHttp() {
    Il2Cpp.perform(() => {
        try {
             // 4. Hook System.Net.ServicePointManager
            const systemAssembly = Il2Cpp.domain.tryAssembly("System");
            if (systemAssembly) {
                console.log(`${ts()} [*] Scanning System assembly...`);
                const ServicePointManager = systemAssembly.image.tryClass("System.Net.ServicePointManager");
                if (ServicePointManager) {
                    console.log(`${ts()} [+] Found ServicePointManager class`);
                    const getCallback = ServicePointManager.tryMethod("get_ServerCertificateValidationCallback");
                    if (getCallback) {
                        getCallback.implementation = function () {
                            console.log(`${ts()} [ServicePointManager] get_ServerCertificateValidationCallback called`);
                            return this.method("get_ServerCertificateValidationCallback").invoke();
                        };
                        console.log(`${ts()} [+] Hooked ServicePointManager.get_ServerCertificateValidationCallback`);
                    }
                    const checkCert = ServicePointManager.tryMethod("CheckCertificate", 4);
                     if (checkCert) {
                        checkCert.implementation = function (p1: any, p2: any, p3: any, p4: any) {
                             console.log(`${ts()} [ServicePointManager] CheckCertificate called -> Returning true`);
                             return true;
                        };
                        console.log(`${ts()} [+] Hooked ServicePointManager.CheckCertificate`);
                    }
                } else {
                    console.log(`${ts()} [-] System.Net.ServicePointManager NOT found`);
                }

                // 5. Hook System.Net.Security.SslStream
                const SslStream = systemAssembly.image.tryClass("System.Net.Security.SslStream");
                if (SslStream) {
                     console.log(`${ts()} [+] Found SslStream class`);
                     const auth = SslStream.tryMethod("AuthenticateAsClient", 4);
                     if (auth) {
                         auth.implementation = function (host: Il2Cpp.Object, certs: Il2Cpp.Object, proto: any, check: boolean) {
                             console.log(`${ts()} [SslStream] AuthenticateAsClient called for host=${host}`);
                             return this.method("AuthenticateAsClient", 4).invoke(host, certs, proto, check);
                         }
                         console.log(`${ts()} [+] Hooked SslStream.AuthenticateAsClient`);
                     }
                }
            }
        } catch(e) { console.log(`${ts()} [!] SystemHttp hook failed: ${e}`); }
    });
}

function hookUnityCert() {
    Il2Cpp.perform(() => {
        try {
             // 1. Hook UnityEngine.Networking.CertificateHandler
            const assembly = Il2Cpp.domain.tryAssembly("UnityEngine.CoreModule") ||
                Il2Cpp.domain.tryAssembly("UnityEngine.Networking");

            if (assembly) {
                const CertificateHandler = assembly.image.tryClass("UnityEngine.Networking.CertificateHandler");
                if (CertificateHandler) {
                    const validateMethod = CertificateHandler.tryMethod("ValidateCertificate", 1);
                    if (validateMethod) {
                        validateMethod.implementation = function (certificateData: Il2Cpp.Object) {
                            console.log(`${ts()} [CertificateHandler] ValidateCertificate called -> Bypassing`);
                            return true;
                        };
                        console.log(`${ts()} [+] CertificateHandler.ValidateCertificate hooked`);
                    }
                }
            }
        } catch(e) { console.log(`${ts()} [!] UnityCert hook failed: ${e}`); }
    });
}

setImmediate(() => {
    try {
        hookLibc();
    } catch (e) { console.log(`[!] hookLibc failed: ${e}`); }
    
    try {
        console.log(`${ts()} [*] Enabling NativeTlsBypass...`);
        NativeTlsBypass.enable(true);
    } catch (e) { console.log(`[!] NativeTlsBypass failed: ${e}`); }
    
    setTimeout(() => {
        try {
            console.log(`${ts()} [*] Hooking System HTTP (ServicePointManager)...`);
            hookSystemHttp();
        } catch (e) { console.log(`[!] hookSystemHttp failed: ${e}`); }
        
        try {
            console.log(`${ts()} [*] Hooking Unity CertificateHandler...`);
            hookUnityCert();
        } catch (e) { console.log(`[!] hookUnityCert failed: ${e}`); }
    }, 3000); // 3s delay
});

