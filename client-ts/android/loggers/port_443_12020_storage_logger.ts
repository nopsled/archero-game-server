/**
 * Combined Startup Logger - Port 443 + 12020 + Storage
 * 
 * Comprehensive logger for Archero startup that captures:
 * - TLS traffic (port 443) with hostname resolution
 * - Game protocol packets (port 12020) with field dumps
 * - Storage operations (files, prefs, assets, save data)
 * 
 * Designed for developing a private server emulator/sandbox.
 * 
 * Usage:
 *   cd client-ts
 *   bun run startup:log
 */

/// <reference path="../../frida.d.ts" />

import "frida-il2cpp-bridge";

console.log("╔══════════════════════════════════════════════════════════════╗");
console.log("║     ARCHERO COMBINED STARTUP LOGGER                         ║");
console.log("║     Network (443+12020) + Storage + Packets                 ║");
console.log("╚══════════════════════════════════════════════════════════════╝");

// =============================================================================
// CONFIGURATION
// =============================================================================

const DISCOVERY_DURATION_MS = 90000;
const MAX_CAPTURE_BYTES = 4096;
const FILTER_ADS = true;
const LOG_STORAGE = true;
const LOG_FILE_IO = true;
const MAX_PREVIEW_LEN = 128;

// Storage paths to capture
const INTERESTING_PATHS = [
    "/data/", "shared_prefs", ".json", ".dat", ".xml", ".bin", ".save", "archero", "habby",
];
const IGNORE_PATHS = ["/proc/", "/sys/", "/dev/", "libfrida", ".so", ".dex", ".odex"];

// =============================================================================
// HOST CLASSIFICATION (for TLS traffic)
// =============================================================================

type HostClass = "game" | "analytics" | "ads" | "unknown";

const GAME_HOSTS = ["habby.mobi", "habby.com", "archero", "archerosvc.com"];
const AD_HOSTS = [
    "applovin.com", "facebook.com", "fbcdn.net", "googleadservices.com", "doubleclick.net",
    "unityads.unity3d.com", "moloco.com", "vungle.com", "mopub.com", "admob", "crashlytics",
    "fundingchoicesmessages", "app-measurement",
];
const ANALYTICS_HOSTS = [
    "receiver.habby.mobi", "adjust.com", "branch.io", "amplitude.com", "mixpanel.com",
    "segment.io", "firebase", "fonts.googleapis.com", "fonts.gstatic.com",
];

function classifyHost(hostname: string): HostClass {
    const lower = hostname.toLowerCase();
    for (const pattern of GAME_HOSTS) {
        if (lower.includes(pattern)) {
            if (lower.includes("receiver.habby.mobi")) return "analytics";
            return "game";
        }
    }
    for (const pattern of ANALYTICS_HOSTS) if (lower.includes(pattern)) return "analytics";
    for (const pattern of AD_HOSTS) if (lower.includes(pattern)) return "ads";
    return "unknown";
}

function shouldLogTls(classification: HostClass): boolean {
    if (FILTER_ADS && classification === "ads") return false;
    return true;
}

// =============================================================================
// DATA STRUCTURES
// =============================================================================

interface TlsCapture {
    t: number;
    type: "tls";
    direction: "send" | "recv";
    host: string;
    port: number;
    classification: HostClass;
    bytes: number;
    http?: { method?: string; path?: string; statusCode?: number; contentType?: string; };
    body?: string;
}

interface PacketCapture {
    t: number;
    type: "packet";
    direction: "C→S" | "S→C";
    packetName: string;
    fields: Record<string, any>;
}

interface NetworkEvent {
    t: number;
    type: "dns" | "connect";
    host?: string;
    ip?: string;
    port?: number;
}

interface StorageCapture {
    t: number;
    type: "storage";
    category: "file" | "prefs" | "asset" | "json" | "binary" | "save";
    op: string;
    target: string;
    detail?: string;
}

type Capture = TlsCapture | PacketCapture | NetworkEvent | StorageCapture;

const captures: Capture[] = [];

// State tracking
let startTime = 0;
const fdToAddr = new Map<number, { ip: string; port: number }>();
const ipToHostname = new Map<string, string>();
const sslToFd = new Map<string, number>();
const sslToHostname = new Map<string, string>();
const pendingSNI = new Map<number, string>();
const openFds = new Map<number, string>(); // fd -> file path
let SSL_get_fd: NativeFunction<number, [NativePointer]> | null = null;

// Stats
const stats = {
    tls: { total: 0, game: 0, analytics: 0, ads: 0, unknown: 0, filtered: 0 },
    packets: { sent: 0, received: 0 },
    connections: 0,
    loginSent: false,
    loginReceived: false,
    storage: { file: 0, prefs: 0, asset: 0, json: 0, binary: 0, save: 0 },
};

// Storage tracking
const prefsKeys: string[] = [];
const assetBundles: string[] = [];
const saveDataEvents: string[] = [];

// =============================================================================
// HELPERS
// =============================================================================

function elapsed(): number { return (Date.now() - startTime) / 1000; }
function ts(): string { return `[${elapsed().toFixed(2)}s]`; }

function safeString(val: any): string {
    if (val === null || val === undefined) return "null";
    try {
        if (val.class?.name === "String") return JSON.stringify(val.content ?? "");
        return String(val);
    } catch { return "<error>"; }
}

function preview(str: string, len = MAX_PREVIEW_LEN): string {
    return str.length > len ? str.substring(0, len) + "..." : str;
}

function isInterestingPath(path: string): boolean {
    if (!path) return false;
    for (const p of IGNORE_PATHS) if (path.includes(p)) return false;
    for (const p of INTERESTING_PATHS) if (path.toLowerCase().includes(p.toLowerCase())) return true;
    return false;
}

function bufferToString(buffer: ArrayBuffer, maxLen = 2048): string {
    const bytes = new Uint8Array(buffer);
    const length = Math.min(bytes.length, maxLen);
    let str = "";
    for (let i = 0; i < length; i++) str += String.fromCharCode(bytes[i]);
    return str;
}

// =============================================================================
// HTTP/TLS PARSING
// =============================================================================

function parseHttpRequest(data: ArrayBuffer): { method?: string; path?: string; contentType?: string } | null {
    try {
        const str = bufferToString(data, 1024);
        const match = str.match(/^(GET|POST|PUT|DELETE|PATCH)\s+(\S+)\s+HTTP/);
        if (!match) return null;
        const ctMatch = str.match(/\r\nContent-Type:\s*([^\r\n]+)/i);
        return { method: match[1], path: match[2], contentType: ctMatch?.[1] };
    } catch { return null; }
}

function parseHttpResponse(data: ArrayBuffer): { statusCode?: number; contentType?: string } | null {
    try {
        const str = bufferToString(data, 1024);
        const match = str.match(/^HTTP\/[\d.]+\s+(\d+)/);
        if (!match) return null;
        const ctMatch = str.match(/\r\nContent-Type:\s*([^\r\n]+)/i);
        return { statusCode: parseInt(match[1]), contentType: ctMatch?.[1] };
    } catch { return null; }
}

function extractBody(data: ArrayBuffer): string | undefined {
    try {
        const str = bufferToString(data, 4096);
        const idx = str.indexOf("\r\n\r\n");
        if (idx < 0) return undefined;
        const body = str.substring(idx + 4, idx + 4 + 1024);
        return body.length > 0 ? body : undefined;
    } catch { return undefined; }
}

function extractHostHeader(data: ArrayBuffer): string | null {
    try {
        const str = bufferToString(data, 512);
        const match = str.match(/\r\nHost:\s*([^\r\n:]+)/i);
        return match ? match[1].trim() : null;
    } catch { return null; }
}

function extractSNI(data: ArrayBuffer): string | null {
    try {
        const bytes = new Uint8Array(data);
        if (bytes.length < 6 || bytes[0] !== 0x16 || bytes[5] !== 0x01) return null;

        let pos = 43; // Skip headers
        if (bytes.length <= pos) return null;

        // Skip session ID, cipher suites, compression
        const sessionLen = bytes[pos]; pos += 1 + sessionLen;
        if (bytes.length <= pos + 2) return null;
        const cipherLen = (bytes[pos] << 8) | bytes[pos + 1]; pos += 2 + cipherLen;
        if (bytes.length <= pos + 1) return null;
        const compLen = bytes[pos]; pos += 1 + compLen;
        if (bytes.length <= pos + 2) return null;

        // Extensions
        const extLen = (bytes[pos] << 8) | bytes[pos + 1]; pos += 2;
        const extEnd = pos + extLen;

        while (pos + 4 < extEnd && pos + 4 < bytes.length) {
            const extType = (bytes[pos] << 8) | bytes[pos + 1];
            const extDataLen = (bytes[pos + 2] << 8) | bytes[pos + 3];
            pos += 4;

            if (extType === 0 && pos + 5 < bytes.length) { // SNI
                const nameLen = (bytes[pos + 3] << 8) | bytes[pos + 4];
                if (pos + 5 + nameLen <= bytes.length) {
                    let hostname = "";
                    for (let i = 0; i < nameLen; i++) hostname += String.fromCharCode(bytes[pos + 5 + i]);
                    return hostname;
                }
            }
            pos += extDataLen;
        }
    } catch { }
    return null;
}

// =============================================================================
// IL2CPP FIELD DUMPING
// =============================================================================

function dumpAllFields(instance: any, depth = 0): Record<string, any> {
    if (depth > 2) return { _depth: "max" };
    const result: Record<string, any> = {};
    try {
        if (!instance || !instance.class) return result;
        instance.class.fields.forEach((field: any) => {
            if (field.isStatic) return;
            const fieldName = field.name;
            const typeName = field.type?.name || "unknown";
            try {
                const value = instance.field(fieldName).value;
                if (value === null || value === undefined) { result[fieldName] = null; return; }
                if (typeName === "String") { result[fieldName] = value.content ?? null; return; }
                if (typeName === "Boolean" || typeName === "bool") { result[fieldName] = !!value; return; }
                if (["Int32", "UInt32", "Int64", "UInt64", "Int16", "UInt16", "Byte", "SByte", "Single", "Double"].includes(typeName)) {
                    result[fieldName] = Number(value); return;
                }
                if (typeName === "Byte[]") {
                    const len = value.length || 0;
                    if (len > 0 && len <= 128) {
                        let hex = "";
                        for (let i = 0; i < Math.min(len, 32); i++) hex += value.get(i).toString(16).padStart(2, "0");
                        if (len > 32) hex += `...(${len})`;
                        result[fieldName] = { type: "byte[]", len, hex };
                    } else {
                        result[fieldName] = { type: "byte[]", len };
                    }
                    return;
                }
                if (typeName.endsWith("[]")) { result[fieldName] = { type: typeName, len: value.length || 0 }; return; }
                if (typeName.startsWith("List`1") || typeName.startsWith("Dictionary`2")) {
                    try { result[fieldName] = { type: typeName.split("`")[0], count: Number(value.method("get_Count").invoke()) }; }
                    catch { result[fieldName] = { type: typeName.split("`")[0] }; }
                    return;
                }
                if (value.class && depth < 2) {
                    const nested = dumpAllFields(value, depth + 1);
                    if (Object.keys(nested).length > 0) result[fieldName] = { type: typeName, fields: nested };
                    return;
                }
                result[fieldName] = safeString(value);
            } catch { result[fieldName] = `<error>`; }
        });
    } catch { }
    return result;
}

function printFields(fields: Record<string, any>, indent = "│   "): void {
    for (const [key, value] of Object.entries(fields)) {
        if (value && typeof value === "object" && value.fields) {
            console.log(`${ts()} ${indent}${key}: {${value.type}}`);
            printFields(value.fields, indent + "  ");
        } else if (value && typeof value === "object" && value.type) {
            const extra = value.len !== undefined ? `, len=${value.len}` : value.count !== undefined ? `, count=${value.count}` : "";
            const hex = value.hex ? ` [${value.hex.substring(0, 24)}...]` : "";
            console.log(`${ts()} ${indent}${key}: ${value.type}${extra}${hex}`);
        } else {
            const display = JSON.stringify(value);
            console.log(`${ts()} ${indent}${key}: ${display.length > 60 ? display.substring(0, 60) + "..." : display}`);
        }
    }
}

// =============================================================================
// HOST RESOLUTION
// =============================================================================

function getHostForFd(fd: number): { host: string; port: number } {
    const addr = fdToAddr.get(fd);
    if (addr) {
        const sni = pendingSNI.get(fd);
        if (sni) return { host: sni, port: addr.port };
        const dns = ipToHostname.get(addr.ip);
        if (dns) return { host: dns, port: addr.port };
        return { host: addr.ip, port: addr.port };
    }
    return { host: "unknown", port: 443 };
}

function getHostForSSL(ssl: NativePointer, data?: ArrayBuffer): { host: string; port: number } {
    const sslKey = ssl.toString();
    const cached = sslToHostname.get(sslKey);
    if (cached) {
        const fd = sslToFd.get(sslKey);
        return { host: cached, port: fd !== undefined ? fdToAddr.get(fd)?.port || 443 : 443 };
    }

    let fd = sslToFd.get(sslKey) ?? -1;
    if (fd < 0 && SSL_get_fd) {
        try { fd = SSL_get_fd(ssl); if (fd >= 0) sslToFd.set(sslKey, fd); } catch { }
    }

    if (data) {
        const sni = extractSNI(data);
        if (sni) {
            sslToHostname.set(sslKey, sni);
            if (fd >= 0) {
                pendingSNI.set(fd, sni);
                const addr = fdToAddr.get(fd);
                if (addr && !ipToHostname.has(addr.ip)) ipToHostname.set(addr.ip, sni);
            }
            return { host: sni, port: fd >= 0 ? fdToAddr.get(fd)?.port || 443 : 443 };
        }

        const host = extractHostHeader(data);
        if (host) {
            sslToHostname.set(sslKey, host);
            if (fd >= 0) {
                const addr = fdToAddr.get(fd);
                if (addr && !ipToHostname.has(addr.ip)) ipToHostname.set(addr.ip, host);
            }
            return { host, port: fd >= 0 ? fdToAddr.get(fd)?.port || 443 : 443 };
        }
    }

    if (fd >= 0) return getHostForFd(fd);
    return { host: "unknown", port: 443 };
}

// =============================================================================
// STORAGE LOGGING HELPER
// =============================================================================

function logStorage(category: StorageCapture["category"], op: string, target: string, detail?: string): void {
    if (!LOG_STORAGE) return;
    const icon = { file: "📂", prefs: "🔑", asset: "📦", json: "📋", binary: "💾", save: "💿" }[category] || "📁";
    console.log(`${ts()} [${category.toUpperCase().padEnd(6)}] ${icon} ${op}: ${preview(target, 50)}`);
    if (detail) console.log(`${ts()}   └─ ${preview(detail, 80)}`);

    stats.storage[category]++;
    captures.push({ t: elapsed(), type: "storage", category, op, target: target.substring(0, 200), detail: detail?.substring(0, 100) });
}

// =============================================================================
// NATIVE HOOKS: DNS + CONNECT + TLS
// =============================================================================

function hookNativeNetwork(): void {
    console.log("[NATIVE] Setting up network hooks...");
    const libc = Process.getModuleByName("libc.so");

    // getaddrinfo
    try {
        const ptr = libc.findExportByName("getaddrinfo");
        if (ptr) {
            Interceptor.attach(ptr, {
                onEnter(args) {
                    try { (this as any).hostname = args[0].readUtf8String(); (this as any).result = args[3]; }
                    catch { (this as any).hostname = null; }
                },
                onLeave(retval) {
                    try {
                        const hostname = (this as any).hostname;
                        const resultPtr = (this as any).result;
                        if (hostname && retval.toInt32() === 0 && resultPtr) {
                            let ai = resultPtr.readPointer();
                            let count = 0;
                            while (!ai.isNull() && count < 50) {
                                count++;
                                try {
                                    const family = ai.add(4).readS32();
                                    if (family === 2) {
                                        const addr = ai.add(Process.pointerSize === 8 ? 24 : 16).readPointer();
                                        if (!addr.isNull()) {
                                            const ip = `${addr.add(4).readU8()}.${addr.add(5).readU8()}.${addr.add(6).readU8()}.${addr.add(7).readU8()}`;
                                            ipToHostname.set(ip, hostname);
                                        }
                                    }
                                    ai = ai.add(Process.pointerSize === 8 ? 40 : 28).readPointer();
                                } catch { break; }
                            }
                            captures.push({ t: elapsed(), type: "dns", host: hostname });
                        }
                    } catch { }
                },
            });
            console.log("   ✓ getaddrinfo");
        }
    } catch { }

    // gethostbyname
    try {
        const ptr = libc.findExportByName("gethostbyname");
        if (ptr) {
            Interceptor.attach(ptr, {
                onEnter(args) { try { (this as any).hostname = args[0].readUtf8String(); } catch { (this as any).hostname = null; } },
                onLeave(retval) {
                    try {
                        const hostname = (this as any).hostname;
                        if (hostname && !retval.isNull()) {
                            const addrListOffset = Process.pointerSize === 8 ? 24 : 16;
                            const addrList = retval.add(addrListOffset).readPointer();
                            if (!addrList.isNull()) {
                                const addrPtr = addrList.readPointer();
                                if (!addrPtr.isNull()) {
                                    const ip = `${addrPtr.readU8()}.${addrPtr.add(1).readU8()}.${addrPtr.add(2).readU8()}.${addrPtr.add(3).readU8()}`;
                                    ipToHostname.set(ip, hostname);
                                }
                            }
                        }
                    } catch { }
                },
            });
            console.log("   ✓ gethostbyname");
        }
    } catch { }

    // android_getaddrinfofornet
    try {
        const ptr = libc.findExportByName("android_getaddrinfofornet");
        if (ptr) {
            Interceptor.attach(ptr, {
                onEnter(args) { try { (this as any).hostname = args[0].readUtf8String(); (this as any).result = args[3]; } catch { } },
                onLeave(retval) {
                    try {
                        const hostname = (this as any).hostname;
                        const resultPtr = (this as any).result;
                        if (hostname && retval.toInt32() === 0 && resultPtr) {
                            let ai = resultPtr.readPointer();
                            if (!ai.isNull()) {
                                const family = ai.add(4).readS32();
                                if (family === 2) {
                                    const addr = ai.add(Process.pointerSize === 8 ? 24 : 16).readPointer();
                                    if (!addr.isNull()) {
                                        const ip = `${addr.add(4).readU8()}.${addr.add(5).readU8()}.${addr.add(6).readU8()}.${addr.add(7).readU8()}`;
                                        ipToHostname.set(ip, hostname);
                                    }
                                }
                            }
                        }
                    } catch { }
                },
            });
            console.log("   ✓ android_getaddrinfofornet");
        }
    } catch { }

    // connect
    try {
        const ptr = libc.findExportByName("connect");
        if (ptr) {
            Interceptor.attach(ptr, {
                onEnter(args) {
                    try {
                        const fd = args[0].toInt32();
                        const sockaddr = args[1];
                        const family = sockaddr.readU16();
                        if (family === 2) {
                            const portBE = sockaddr.add(2).readU16();
                            const port = ((portBE & 0xff) << 8) | ((portBE >> 8) & 0xff);
                            const ip = `${sockaddr.add(4).readU8()}.${sockaddr.add(5).readU8()}.${sockaddr.add(6).readU8()}.${sockaddr.add(7).readU8()}`;
                            fdToAddr.set(fd, { ip, port });
                            if (port === 443 || port === 12020) {
                                stats.connections++;
                                const hostname = ipToHostname.get(ip) || ip;
                                captures.push({ t: elapsed(), type: "connect", ip, port, host: hostname });
                                console.log(`${ts()} [CONNECT] ${hostname}:${port}`);
                            }
                        }
                    } catch { }
                },
            });
            console.log("   ✓ connect");
        }
    } catch { }
}

// =============================================================================
// NATIVE HOOKS: File I/O
// =============================================================================

function hookNativeFileIO(): void {
    if (!LOG_FILE_IO) return;
    console.log("[NATIVE] Setting up file I/O hooks...");

    try {
        const openPtr = Module.findExportByName(null, "open");
        if (openPtr) {
            Interceptor.attach(openPtr, {
                onEnter(args) { try { (this as any).path = args[0].readUtf8String(); } catch { (this as any).path = null; } },
                onLeave(retval) {
                    try {
                        const fd = retval.toInt32();
                        if (fd >= 0 && (this as any).path && isInterestingPath((this as any).path)) {
                            openFds.set(fd, (this as any).path);
                            logStorage("file", "open", (this as any).path);
                        }
                    } catch { }
                },
            });
            console.log("   ✓ open()");
        }

        const closePtr = Module.findExportByName(null, "close");
        if (closePtr) {
            Interceptor.attach(closePtr, {
                onEnter(args) { try { (this as any).fd = args[0].toInt32(); } catch { (this as any).fd = -1; } },
                onLeave() { try { openFds.delete((this as any).fd); } catch { } },
            });
            console.log("   ✓ close()");
        }
    } catch (e) {
        console.log(`   ✗ File I/O hooks failed: ${e}`);
    }
}

// =============================================================================
// TLS HOOKS
// =============================================================================

function hookTLS(): void {
    console.log("[NATIVE] Setting up TLS hooks...");
    const modules = Process.enumerateModules();

    const sslModules = modules.filter(mod => {
        const name = mod.name.toLowerCase();
        return name.includes("ssl") || name.includes("crypto");
    });

    for (const mod of sslModules) {
        try {
            const getFdPtr = mod.findExportByName("SSL_get_fd");
            if (getFdPtr) {
                SSL_get_fd = new NativeFunction(getFdPtr, "int", ["pointer"]);
                console.log("   ✓ SSL_get_fd");
            }
        } catch { }

        try {
            const setFdPtr = mod.findExportByName("SSL_set_fd");
            if (setFdPtr) {
                Interceptor.attach(setFdPtr, {
                    onEnter(args) { sslToFd.set(args[0].toString(), args[1].toInt32()); },
                });
                console.log("   ✓ SSL_set_fd");
            }
        } catch { }

        try {
            const ctrlPtr = mod.findExportByName("SSL_ctrl");
            if (ctrlPtr) {
                Interceptor.attach(ctrlPtr, {
                    onEnter(args) {
                        try {
                            const cmd = args[1].toInt32();
                            if (cmd === 55) { // SSL_CTRL_SET_TLSEXT_HOSTNAME
                                const hostname = args[3].readUtf8String();
                                if (hostname) {
                                    const sslKey = args[0].toString();
                                    sslToHostname.set(sslKey, hostname);
                                    const fd = sslToFd.get(sslKey);
                                    if (fd !== undefined) {
                                        const addr = fdToAddr.get(fd);
                                        if (addr) ipToHostname.set(addr.ip, hostname);
                                    }
                                }
                            }
                        } catch { }
                    },
                });
                console.log("   ✓ SSL_ctrl (SNI)");
            }
        } catch { }

        try {
            const sslRead = mod.findExportByName("SSL_read");
            if (sslRead) {
                Interceptor.attach(sslRead, {
                    onEnter(args) { (this as any).ssl = args[0]; (this as any).buf = args[1]; },
                    onLeave(retval) {
                        const ret = retval.toInt32();
                        if (ret > 0) {
                            const data = (this as any).buf.readByteArray(Math.min(ret, MAX_CAPTURE_BYTES));
                            if (data) {
                                let { host, port } = getHostForSSL((this as any).ssl);

                                if (host === "unknown") {
                                    const sslKey = ((this as any).ssl as NativePointer).toString();
                                    let fd = sslToFd.get(sslKey);
                                    if (fd === undefined && SSL_get_fd) {
                                        try { fd = SSL_get_fd((this as any).ssl); if (fd >= 0) sslToFd.set(sslKey, fd); } catch { }
                                    }
                                    if (fd !== undefined) {
                                        const addr = fdToAddr.get(fd);
                                        if (addr) {
                                            const cachedHost = ipToHostname.get(addr.ip);
                                            if (cachedHost) { host = cachedHost; sslToHostname.set(sslKey, host); }
                                            port = addr.port;
                                        }
                                    }
                                }

                                const classification = classifyHost(host);
                                stats.tls.total++; stats.tls[classification]++;
                                if (!shouldLogTls(classification)) { stats.tls.filtered++; return; }

                                const http = parseHttpResponse(data);
                                const capture: TlsCapture = { t: elapsed(), type: "tls", direction: "recv", host, port, classification, bytes: ret, http: http || undefined };
                                const body = extractBody(data);
                                if (body) capture.body = body.substring(0, 500);
                                captures.push(capture);

                                console.log(`${ts()} [TLS:RECV] ← ${host}:${port} [${classification.toUpperCase()}] (${ret}B)`);
                                if (http?.statusCode) console.log(`   HTTP ${http.statusCode}`);
                            }
                        }
                    },
                });
                console.log("   ✓ SSL_read");
            }
        } catch { }

        try {
            const sslWrite = mod.findExportByName("SSL_write");
            if (sslWrite) {
                Interceptor.attach(sslWrite, {
                    onEnter(args) { (this as any).ssl = args[0]; (this as any).buf = args[1]; (this as any).num = args[2].toInt32(); },
                    onLeave(retval) {
                        const ret = retval.toInt32();
                        if (ret > 0) {
                            const data = (this as any).buf.readByteArray(Math.min(ret, MAX_CAPTURE_BYTES));
                            if (data) {
                                const { host, port } = getHostForSSL((this as any).ssl, data);
                                const classification = classifyHost(host);
                                stats.tls.total++; stats.tls[classification]++;
                                if (!shouldLogTls(classification)) { stats.tls.filtered++; return; }

                                const http = parseHttpRequest(data);
                                const capture: TlsCapture = { t: elapsed(), type: "tls", direction: "send", host, port, classification, bytes: ret, http: http || undefined };
                                const body = extractBody(data);
                                if (body) capture.body = body.substring(0, 500);
                                captures.push(capture);

                                console.log(`${ts()} [TLS:SEND] → ${host}:${port} [${classification.toUpperCase()}] (${ret}B)`);
                                if (http?.method) console.log(`   ${http.method} ${http.path}`);
                            }
                        }
                    },
                });
                console.log("   ✓ SSL_write");
            }
        } catch { }

        break; // Only first SSL lib
    }
}

// =============================================================================
// IL2CPP HOOKS: Game Protocol
// =============================================================================

function hookGameProtocol(): void {
    console.log("[IL2CPP] Waiting for runtime...");

    Il2Cpp.perform(() => {
        startTime = Date.now();
        console.log(`${ts()} [IL2CPP] Runtime ready, installing hooks...`);

        try {
            const asm = Il2Cpp.domain.assembly("Assembly-CSharp").image;
            hookLoginPackets(asm);
            hookTcpNetManager(asm);
            hookEncryption(asm);
            hookStorage(asm);

            console.log(`\n${ts()} [READY] All hooks installed. Capturing for ${DISCOVERY_DURATION_MS / 1000}s...`);
            console.log("═".repeat(66));

            setTimeout(() => printSummary(), DISCOVERY_DURATION_MS);
        } catch (e) {
            console.log(`${ts()} [ERROR] Failed to hook IL2CPP: ${e}`);
        }
    });
}

function hookLoginPackets(asm: Il2Cpp.Image): void {
    console.log(`${ts()} [HOOK] Login packets...`);

    const packets = [
        "GameProtocol.CUserLoginPacket",
        "GameProtocol.CRespUserLoginPacket",
        "GameProtocol.CHeartBeatPacket",
        "GameProtocol.CRespHeartBeat",
    ];

    for (const packetName of packets) {
        try {
            const cls = asm.class(packetName);
            const shortName = packetName.split(".").pop()!;

            try {
                cls.method("WriteToStream").implementation = function (...args: any[]) {
                    console.log(`\n${ts()} ┌───────────────────────────────────────────`);
                    console.log(`${ts()} │ 📤 PACKET OUT: ${(this as any).class.name}`);
                    console.log(`${ts()} ├───────────────────────────────────────────`);

                    const fields = dumpAllFields(this);
                    printFields(fields);
                    console.log(`${ts()} └───────────────────────────────────────────\n`);

                    if ((this as any).class.name === "CUserLoginPacket") stats.loginSent = true;
                    stats.packets.sent++;
                    captures.push({ t: elapsed(), type: "packet", direction: "C→S", packetName: (this as any).class.name, fields });

                    return this.method("WriteToStream").invoke(...args);
                };
                console.log(`${ts()}   ✓ ${shortName}.WriteToStream`);
            } catch { }

            try {
                cls.method("ReadFromStream").implementation = function (...args: any[]) {
                    const result = this.method("ReadFromStream").invoke(...args);

                    console.log(`\n${ts()} ┌───────────────────────────────────────────`);
                    console.log(`${ts()} │ 📥 PACKET IN: ${(this as any).class.name}`);
                    console.log(`${ts()} ├───────────────────────────────────────────`);

                    const fields = dumpAllFields(this);
                    printFields(fields);
                    console.log(`${ts()} └───────────────────────────────────────────\n`);

                    if ((this as any).class.name === "CRespUserLoginPacket") stats.loginReceived = true;
                    stats.packets.received++;
                    captures.push({ t: elapsed(), type: "packet", direction: "S→C", packetName: (this as any).class.name, fields });

                    return result;
                };
                console.log(`${ts()}   ✓ ${shortName}.ReadFromStream`);
            } catch { }
        } catch { }
    }
}

function hookTcpNetManager(asm: Il2Cpp.Image): void {
    console.log(`${ts()} [HOOK] TcpNetManager...`);

    try {
        const tcpMgr = asm.class("TcpNetManager");
        tcpMgr.method("SendPacket").implementation = function (packet: Il2Cpp.Object) {
            try {
                const packetClass = packet.class;
                const packetName = packetClass.name;

                console.log(`\n${ts()} ┌───────────────────────────────────────────`);
                console.log(`${ts()} │ 📤 PACKET OUT: ${packetName}`);
                console.log(`${ts()} ├───────────────────────────────────────────`);

                const fields = dumpAllFields(packet);
                printFields(fields);
                console.log(`${ts()} └───────────────────────────────────────────\n`);

                stats.packets.sent++;
                captures.push({ t: elapsed(), type: "packet", direction: "C→S", packetName, fields });
            } catch { }

            return this.method("SendPacket").invoke(packet);
        };
        console.log(`${ts()}   ✓ TcpNetManager.SendPacket`);
    } catch { }
}

function hookEncryption(asm: Il2Cpp.Image): void {
    console.log(`${ts()} [HOOK] Encryption...`);

    try {
        const rc4 = asm.class("RC4Encrypter");
        rc4.method(".ctor").implementation = function (...args: any[]) {
            const result = this.method(".ctor").invoke(...args);
            try {
                const key = this.field("m_arrayKey").value as any;
                if (key) {
                    let keyHex = "";
                    const len = Math.min(key.length || 0, 16);
                    for (let i = 0; i < len; i++) keyHex += key.get(i).toString(16).padStart(2, "0");
                    console.log(`${ts()} [CRYPTO] RC4 key: ${keyHex}`);
                }
            } catch { }
            return result;
        };
        console.log(`${ts()}   ✓ RC4Encrypter.ctor`);
    } catch { }
}

// =============================================================================
// IL2CPP HOOKS: Storage
// =============================================================================

function hookStorage(asm: Il2Cpp.Image): void {
    if (!LOG_STORAGE) return;
    console.log(`${ts()} [HOOK] Storage...`);

    // LocalSave
    try {
        const localSave = asm.class("LocalSave");
        try {
            localSave.method("InitSaveData").implementation = function () {
                logStorage("save", "InitSaveData", "LocalSave");
                saveDataEvents.push("InitSaveData");
                return this.method("InitSaveData").invoke();
            };
            console.log(`${ts()}   ✓ LocalSave.InitSaveData`);
        } catch { }
        try {
            localSave.method("SaveDataRefresh").implementation = function () {
                logStorage("save", "SaveDataRefresh", "LocalSave");
                saveDataEvents.push("SaveDataRefresh");
                return this.method("SaveDataRefresh").invoke();
            };
            console.log(`${ts()}   ✓ LocalSave.SaveDataRefresh`);
        } catch { }
    } catch { }

    // PlayerPrefsEncrypt
    try {
        const prefsEncrypt = asm.class("PlayerPrefsEncrypt");
        const getMethods = ["GetString", "GetInt", "GetBool", "GetLong", "GetFloat"];
        for (const m of getMethods) {
            try {
                prefsEncrypt.method(m).implementation = function (...args: any[]) {
                    const key = safeString(args[0]);
                    const result = this.method(m).invoke(...args);
                    const value = safeString(result);
                    logStorage("prefs", `${m}`, key, value);
                    if (!prefsKeys.includes(key)) prefsKeys.push(key);
                    return result;
                };
            } catch { }
        }
        const setMethods = ["SetString", "SetInt", "SetBool", "SetLong", "SetFloat"];
        for (const m of setMethods) {
            try {
                prefsEncrypt.method(m).implementation = function (...args: any[]) {
                    const key = safeString(args[0]);
                    const value = args.length > 1 ? safeString(args[1]) : "";
                    logStorage("prefs", `${m}`, key, value);
                    if (!prefsKeys.includes(key)) prefsKeys.push(key);
                    return this.method(m).invoke(...args);
                };
            } catch { }
        }
        console.log(`${ts()}   ✓ PlayerPrefsEncrypt`);
    } catch { }

    // ResourceManager
    try {
        const resourceMgr = asm.class("ResourceManager");
        resourceMgr.method("GetAssetBundle").implementation = function (...args: any[]) {
            const name = safeString(args[0]);
            logStorage("asset", "GetAssetBundle", name);
            if (!assetBundles.includes(name)) assetBundles.push(name);
            return this.method("GetAssetBundle").invoke(...args);
        };
        console.log(`${ts()}   ✓ ResourceManager.GetAssetBundle`);
    } catch { }
}

// =============================================================================
// SUMMARY
// =============================================================================

function printSummary(): void {
    const totalTime = elapsed();

    console.log("\n\n");
    console.log("╔══════════════════════════════════════════════════════════════╗");
    console.log("║               COMBINED CAPTURE SUMMARY                       ║");
    console.log("╚══════════════════════════════════════════════════════════════╝");

    console.log(`\n📊 Statistics:`);
    console.log(`   Duration: ${totalTime.toFixed(1)}s`);
    console.log(`   Login sent: ${stats.loginSent ? "✓" : "✗"} | Login received: ${stats.loginReceived ? "✓" : "✗"}`);
    console.log(`   Connections: ${stats.connections}`);
    console.log(`   TLS: ${stats.tls.total} (game=${stats.tls.game}, analytics=${stats.tls.analytics}, filtered=${stats.tls.filtered})`);
    console.log(`   Packets: sent=${stats.packets.sent}, received=${stats.packets.received}`);

    if (LOG_STORAGE) {
        const storageTotal = Object.values(stats.storage).reduce((a, b) => a + b, 0);
        console.log(`   Storage: ${storageTotal} (file=${stats.storage.file}, prefs=${stats.storage.prefs}, asset=${stats.storage.asset}, save=${stats.storage.save})`);
    }

    console.log(`\n📊 TLS Traffic by Host:`);
    const hostCounts = new Map<string, number>();
    captures.filter(c => c.type === "tls").forEach((c: any) => {
        hostCounts.set(c.host, (hostCounts.get(c.host) || 0) + 1);
    });
    Array.from(hostCounts.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 15)
        .forEach(([host, count]) => console.log(`   ${host}: ${count}`));

    console.log(`\n📊 Game Packets:`);
    captures
        .filter(c => c.type === "packet")
        .slice(0, 50)
        .forEach((c: PacketCapture) => {
            console.log(`   [${c.t.toFixed(2)}s] ${c.direction} ${c.packetName}`);
        });

    if (LOG_STORAGE && prefsKeys.length > 0) {
        console.log(`\n🔑 PlayerPrefs Keys (${prefsKeys.length}):`);
        prefsKeys.slice(0, 10).forEach(k => console.log(`   - ${k}`));
        if (prefsKeys.length > 10) console.log(`   ... and ${prefsKeys.length - 10} more`);
    }

    console.log(`\n📁 JSON Output (${captures.length} events):`);
    console.log("=== BEGIN JSON ===");
    for (const c of captures) console.log(JSON.stringify(c));
    console.log("=== END JSON ===");
}

// =============================================================================
// MAIN
// =============================================================================

hookNativeNetwork();
hookNativeFileIO();
hookTLS();
hookGameProtocol();
