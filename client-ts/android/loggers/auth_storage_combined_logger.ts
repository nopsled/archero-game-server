/**
 * Combined Discovery Tool - Android
 *
 * Comprehensive discovery combining auth flow and storage operations.
 * Captures the first 30 seconds of app launch for private server development.
 *
 * Usage:
 *   cd client-ts
 *   bun run combined-discovery
 */

/// <reference path="../../frida.d.ts" />

import "frida-il2cpp-bridge";

console.log("╔══════════════════════════════════════════════════════════════╗");
console.log("║     ARCHERO COMBINED DISCOVERY (Android)                     ║");
console.log("║     Full capture: Auth + Storage + Network (30s)             ║");
console.log("╚══════════════════════════════════════════════════════════════╝");

// =============================================================================
// CONFIGURATION
// =============================================================================

const DISCOVERY_DURATION_MS = 30000;
const LOG_CONTENT_PREVIEW = true;
const MAX_PREVIEW_LEN = 128;

const INTERESTING_PATHS = [
  "/data/",
  "shared_prefs",
  ".json",
  ".dat",
  ".xml",
  ".bin",
  ".save",
  "archero",
  "habby",
];
const IGNORE_PATHS = ["/proc/", "/sys/", "/dev/", "libfrida", ".so", ".dex", ".odex"];

// =============================================================================
// DATA STRUCTURES
// =============================================================================

interface Event {
  t: number;
  category: string;
  op: string;
  target: string;
  detail?: string;
  fields?: Record<string, any>;
}

const events: Event[] = [];
const openFds = new Map<number, string>();
const dnsLookups = new Map<string, string[]>();
const connections: { ip: string; port: number; t: number }[] = [];
const assetBundles: string[] = [];
const prefsKeys: string[] = [];
const saveDataEvents: string[] = [];
const packetCaptures: { t: number; dir: string; name: string; fields?: Record<string, any> }[] = [];
const encryptionEvents: { t: number; method: string; input: string; output: string }[] = [];

let discoveryStartTime = 0;
let loginPacketSent = false;
let loginResponseReceived = false;

// =============================================================================
// HELPERS
// =============================================================================

function elapsed(): number {
  return (Date.now() - discoveryStartTime) / 1000;
}

function ts(): string {
  return `[${elapsed().toFixed(2)}s]`;
}

function safeString(val: any): string {
  if (val === null || val === undefined) return "<null>";
  try {
    if (val.class && val.class.name === "String") {
      return val.content ?? "<empty>";
    }
    return String(val);
  } catch (e) {
    return "<error>";
  }
}

function isInteresting(path: string): boolean {
  if (!path) return false;
  for (const p of IGNORE_PATHS) if (path.includes(p)) return false;
  for (const p of INTERESTING_PATHS) if (path.toLowerCase().includes(p.toLowerCase())) return true;
  return false;
}

function preview(str: string, len = MAX_PREVIEW_LEN): string {
  return str.length > len ? str.substring(0, len) + "..." : str;
}

function log(category: string, op: string, target: string, detail?: string): void {
  const icons: Record<string, string> = {
    file: "📂",
    prefs: "🔑",
    asset: "📦",
    json: "📋",
    binary: "💾",
    stream: "📖",
    save: "💿",
    crypto: "🔐",
    packet: "📡",
    net: "🌐",
    dns: "🔍",
  };
  const icon = icons[category] || "📁";

  console.log(
    `${ts()} [${category.toUpperCase().padEnd(7)}] ${icon} ${op}: ${preview(target, 50)}`
  );
  if (detail) console.log(`${ts()}   └─ ${preview(detail, 80)}`);

  events.push({
    t: elapsed(),
    category,
    op,
    target: target.substring(0, 200),
    detail: detail?.substring(0, 100),
  });
}

/**
 * Recursively dump all fields from an IL2CPP object
 */
function dumpAllFields(instance: any, depth: number = 0): Record<string, any> {
  if (depth > 2) return { _depth: "max" };

  const result: Record<string, any> = {};

  try {
    if (!instance || !instance.class) return result;

    instance.class.fields.forEach((field: any) => {
      if (field.isStatic) return;

      const fieldName = field.name;
      const typeName = field.type ? field.type.name : "unknown";

      try {
        const value = instance.field(fieldName).value;

        if (value === null || value === undefined) {
          result[fieldName] = null;
          return;
        }

        if (typeName === "String") {
          result[fieldName] = value.content ?? null;
          return;
        }

        if (typeName === "Boolean" || typeName === "bool") {
          result[fieldName] = !!value;
          return;
        }

        if (
          [
            "Int32",
            "UInt32",
            "Int64",
            "UInt64",
            "Int16",
            "UInt16",
            "Byte",
            "SByte",
            "Single",
            "Double",
          ].includes(typeName)
        ) {
          result[fieldName] = Number(value);
          return;
        }

        if (typeName === "Byte[]") {
          const len = value.length || 0;
          if (len > 0 && len <= 256) {
            let hexStr = "";
            for (let i = 0; i < Math.min(len, 32); i++) {
              hexStr += value.get(i).toString(16).padStart(2, "0");
            }
            if (len > 32) hexStr += `...(${len})`;
            result[fieldName] = { type: "byte[]", len, hex: hexStr };
          } else {
            result[fieldName] = { type: "byte[]", len };
          }
          return;
        }

        if (typeName.endsWith("[]")) {
          result[fieldName] = { type: typeName, len: value.length || 0 };
          return;
        }

        if (typeName.startsWith("List`1") || typeName.startsWith("Dictionary`2")) {
          try {
            const count = value.method("get_Count").invoke();
            result[fieldName] = { type: typeName.split("`")[0], count: Number(count) };
          } catch (e) {
            result[fieldName] = { type: typeName.split("`")[0] };
          }
          return;
        }

        if (value.class && depth < 2) {
          const nested = dumpAllFields(value, depth + 1);
          if (Object.keys(nested).length > 0) {
            result[fieldName] = { type: typeName, fields: nested };
          }
          return;
        }

        result[fieldName] = safeString(value);
      } catch (e: any) {
        result[fieldName] = `<error>`;
      }
    });
  } catch (e) {}

  return result;
}

function printFields(fields: Record<string, any>, indent: string = "│   "): void {
  for (const [key, value] of Object.entries(fields)) {
    if (value && typeof value === "object" && value.fields) {
      console.log(`${ts()} ${indent}${key}: {${value.type}}`);
      printFields(value.fields, indent + "  ");
    } else if (value && typeof value === "object" && value.type) {
      const extra =
        value.len !== undefined
          ? `, len=${value.len}`
          : value.count !== undefined
            ? `, count=${value.count}`
            : "";
      const hex = value.hex ? ` [${value.hex.substring(0, 24)}...]` : "";
      console.log(`${ts()} ${indent}${key}: ${value.type}${extra}${hex}`);
    } else {
      const display = JSON.stringify(value);
      console.log(
        `${ts()} ${indent}${key}: ${display.length > 80 ? display.substring(0, 80) + "..." : display}`
      );
    }
  }
}

// =============================================================================
// NATIVE HOOKS: File I/O
// =============================================================================

function hookNativeIO(): void {
  console.log("[NATIVE] Setting up file I/O hooks...");

  try {
    const openPtr = Module.findExportByName(null, "open");
    if (openPtr) {
      Interceptor.attach(openPtr, {
        onEnter(args) {
          try {
            this.path = args[0].readUtf8String();
          } catch (e) {
            this.path = null;
          }
        },
        onLeave(retval) {
          try {
            const fd = retval.toInt32();
            if (fd >= 0 && this.path && isInteresting(this.path)) {
              openFds.set(fd, this.path);
              log("file", "open", this.path);
            }
          } catch (e) {}
        },
      });
      console.log("   ✓ open()");
    }

    const openatPtr = Module.findExportByName(null, "openat");
    if (openatPtr) {
      Interceptor.attach(openatPtr, {
        onEnter(args) {
          try {
            this.path = args[1].readUtf8String();
          } catch (e) {
            this.path = null;
          }
        },
        onLeave(retval) {
          try {
            const fd = retval.toInt32();
            if (fd >= 0 && this.path && isInteresting(this.path)) {
              openFds.set(fd, this.path);
              log("file", "openat", this.path);
            }
          } catch (e) {}
        },
      });
      console.log("   ✓ openat()");
    }

    const readPtr = Module.findExportByName(null, "read");
    if (readPtr) {
      Interceptor.attach(readPtr, {
        onEnter(args) {
          try {
            this.fd = args[0].toInt32();
            this.buf = args[1];
          } catch (e) {
            this.fd = -1;
          }
        },
        onLeave(retval) {
          try {
            const bytes = retval.toInt32();
            const path = openFds.get(this.fd);
            if (bytes > 0 && path) {
              let preview = "";
              if (LOG_CONTENT_PREVIEW) {
                try {
                  const arr = this.buf.readByteArray(Math.min(bytes, 32));
                  if (arr)
                    preview = Array.from(new Uint8Array(arr))
                      .map((b) => b.toString(16).padStart(2, "0"))
                      .join(" ");
                } catch (e) {}
              }
              log("file", `read(${bytes}B)`, path, preview);
            }
          } catch (e) {}
        },
      });
      console.log("   ✓ read()");
    }

    const writePtr = Module.findExportByName(null, "write");
    if (writePtr) {
      Interceptor.attach(writePtr, {
        onEnter(args) {
          try {
            this.fd = args[0].toInt32();
            this.count = args[2].toInt32();
          } catch (e) {
            this.fd = -1;
          }
        },
        onLeave(retval) {
          try {
            const bytes = retval.toInt32();
            const path = openFds.get(this.fd);
            if (bytes > 0 && path) {
              log("file", `write(${bytes}B)`, path);
            }
          } catch (e) {}
        },
      });
      console.log("   ✓ write()");
    }

    const closePtr = Module.findExportByName(null, "close");
    if (closePtr) {
      Interceptor.attach(closePtr, {
        onEnter(args) {
          try {
            this.fd = args[0].toInt32();
          } catch (e) {
            this.fd = -1;
          }
        },
        onLeave() {
          try {
            openFds.delete(this.fd);
          } catch (e) {}
        },
      });
      console.log("   ✓ close()");
    }
  } catch (e) {
    console.log(`   ✗ Native I/O hooks failed: ${e}`);
  }
}

// =============================================================================
// NATIVE HOOKS: Network
// =============================================================================

function hookNativeNetwork(): void {
  console.log("[NATIVE] Setting up network hooks...");

  try {
    const getaddrinfoPtr = Module.findExportByName(null, "getaddrinfo");
    if (getaddrinfoPtr) {
      Interceptor.attach(getaddrinfoPtr, {
        onEnter(args) {
          try {
            this.hostname = args[0].readUtf8String();
          } catch (e) {
            this.hostname = null;
          }
        },
        onLeave(retval) {
          try {
            if (this.hostname && retval.toInt32() === 0) {
              if (!dnsLookups.has(this.hostname)) {
                dnsLookups.set(this.hostname, []);
                log("dns", "resolve", this.hostname);
              }
            }
          } catch (e) {}
        },
      });
      console.log("   ✓ getaddrinfo()");
    }

    const connectPtr = Module.findExportByName(null, "connect");
    if (connectPtr) {
      Interceptor.attach(connectPtr, {
        onEnter(args) {
          try {
            const sockaddr = args[1];
            const family = sockaddr.readU16();

            if (family === 2) {
              // AF_INET
              const portBE = sockaddr.add(2).readU16();
              const port = ((portBE & 0xff) << 8) | ((portBE >> 8) & 0xff);
              const ip = `${sockaddr.add(4).readU8()}.${sockaddr.add(5).readU8()}.${sockaddr.add(6).readU8()}.${sockaddr.add(7).readU8()}`;

              if (port === 443 || port === 12020 || port === 80 || port === 8080 || port > 10000) {
                connections.push({ ip, port, t: elapsed() });
                log("net", "connect", `${ip}:${port}`);
              }
            }
          } catch (e) {}
        },
      });
      console.log("   ✓ connect()");
    }
  } catch (e) {
    console.log(`   ✗ Native network hooks failed: ${e}`);
  }
}

// =============================================================================
// IL2CPP HOOKS
// =============================================================================

function hookIl2Cpp(): void {
  console.log("[IL2CPP] Waiting for runtime...");

  Il2Cpp.perform(() => {
    discoveryStartTime = Date.now();
    console.log(`${ts()} [IL2CPP] Runtime ready, installing hooks...`);

    try {
      const asm = Il2Cpp.domain.assembly("Assembly-CSharp").image;

      hookSystemIO();
      hookUnityPaths();
      hookLocalSave(asm);
      hookPlayerPrefs(asm);
      hookAssetLoading(asm);
      hookJsonSerialization(asm);
      hookStreams();
      hookLoginPackets(asm);
      hookNetworkLayer(asm);
      hookTcpNetManager(asm);
      hookEncryption(asm);

      console.log(
        `\n${ts()} [READY] All hooks installed. Capturing for ${DISCOVERY_DURATION_MS / 1000}s...`
      );
      console.log("═".repeat(66));

      setTimeout(() => printSummary(), DISCOVERY_DURATION_MS);
    } catch (e) {
      console.log(`${ts()} [ERROR] Failed to hook: ${e}`);
    }
  });
}

// =============================================================================
// STORAGE HOOKS
// =============================================================================

function hookSystemIO(): void {
  console.log(`${ts()} [HOOK] System.IO...`);

  try {
    const mscorlib = Il2Cpp.domain.assembly("mscorlib").image;

    try {
      const fileClass = mscorlib.class("System.IO.File");
      const fileMethods = [
        "OpenRead",
        "ReadAllText",
        "WriteAllBytes",
        "Create",
        "Delete",
        "Exists",
      ];
      for (const m of fileMethods) {
        try {
          fileClass.method(m).implementation = function (...args: any[]) {
            const path = args.length > 0 ? safeString(args[0]) : "";
            log("file", `File.${m}`, path);
            return this.method(m).invoke(...args);
          };
          console.log(`${ts()}   ✓ File.${m}`);
        } catch (e) {}
      }
    } catch (e) {}

    try {
      const fileStreamClass = mscorlib.class("System.IO.FileStream");
      fileStreamClass.method(".ctor").implementation = function (...args: any[]) {
        const path = args.length > 0 ? safeString(args[0]) : "";
        log("file", "FileStream.ctor", path);
        return this.method(".ctor").invoke(...args);
      };
      console.log(`${ts()}   ✓ FileStream.ctor`);
    } catch (e) {}
  } catch (e) {}
}

function hookUnityPaths(): void {
  console.log(`${ts()} [HOOK] Unity paths...`);

  try {
    const unityAsm = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image;
    const application = unityAsm.class("UnityEngine.Application");

    for (const pathName of ["persistentDataPath", "dataPath", "temporaryCachePath"]) {
      try {
        application.method(`get_${pathName}`).implementation = function () {
          const result = this.method(`get_${pathName}`).invoke();
          const path = safeString(result);
          log("file", pathName, path);
          return result;
        };
        console.log(`${ts()}   ✓ ${pathName}`);
      } catch (e) {}
    }
  } catch (e) {}
}

function hookLocalSave(asm: Il2Cpp.Image): void {
  console.log(`${ts()} [HOOK] LocalSave...`);

  try {
    const localSave = asm.class("LocalSave");

    for (const m of ["InitSaveData", "SaveDataRefresh"]) {
      try {
        localSave.method(m).implementation = function () {
          log("save", m, "LocalSave");
          saveDataEvents.push(m);
          return this.method(m).invoke();
        };
        console.log(`${ts()}   ✓ LocalSave.${m}`);
      } catch (e) {}
    }
  } catch (e) {}

  try {
    const localSaveBase = asm.class("LocalSaveBase");
    localSaveBase.method("SaveData").implementation = function () {
      log("save", "SaveData", "LocalSaveBase");
      saveDataEvents.push("LocalSaveBase.SaveData");
      return this.method("SaveData").invoke();
    };
    console.log(`${ts()}   ✓ LocalSaveBase.SaveData`);
  } catch (e) {}
}

function hookPlayerPrefs(asm: Il2Cpp.Image): void {
  console.log(`${ts()} [HOOK] PlayerPrefs...`);

  try {
    const prefsEncrypt = asm.class("PlayerPrefsEncrypt");

    const getMethods = ["GetString", "GetInt", "GetBool", "GetLong", "GetFloat"];
    for (const m of getMethods) {
      try {
        prefsEncrypt.method(m).implementation = function (...args: any[]) {
          const key = safeString(args[0]);
          const result = this.method(m).invoke(...args);
          const value = safeString(result);
          log("prefs", m, key, value);
          if (!prefsKeys.includes(key)) prefsKeys.push(key);
          return result;
        };
        console.log(`${ts()}   ✓ PlayerPrefsEncrypt.${m}`);
      } catch (e) {}
    }

    const setMethods = ["SetString", "SetInt", "SetBool", "SetLong", "SetFloat"];
    for (const m of setMethods) {
      try {
        prefsEncrypt.method(m).implementation = function (...args: any[]) {
          const key = safeString(args[0]);
          const value = args.length > 1 ? safeString(args[1]) : "";
          log("prefs", m, key, value);
          if (!prefsKeys.includes(key)) prefsKeys.push(key);
          return this.method(m).invoke(...args);
        };
        console.log(`${ts()}   ✓ PlayerPrefsEncrypt.${m}`);
      } catch (e) {}
    }
  } catch (e) {}
}

function hookAssetLoading(asm: Il2Cpp.Image): void {
  console.log(`${ts()} [HOOK] Asset loading...`);

  try {
    const resourceMgr = asm.class("ResourceManager");
    resourceMgr.method("GetAssetBundle").implementation = function (...args: any[]) {
      const name = safeString(args[0]);
      log("asset", "GetAssetBundle", name);
      if (!assetBundles.includes(name)) assetBundles.push(name);
      return this.method("GetAssetBundle").invoke(...args);
    };
    console.log(`${ts()}   ✓ ResourceManager.GetAssetBundle`);
  } catch (e) {}
}

function hookJsonSerialization(asm: Il2Cpp.Image): void {
  console.log(`${ts()} [HOOK] JSON serialization...`);

  try {
    const newtonsoftAsm = Il2Cpp.domain.assembly("Newtonsoft.Json").image;
    const jsonConvert = newtonsoftAsm.class("Newtonsoft.Json.JsonConvert");

    try {
      jsonConvert.method("SerializeObject").implementation = function (...args: any[]) {
        const result = this.method("SerializeObject").invoke(...args);
        const json = safeString(result);
        log("json", "SerializeObject", preview(json, 60));
        return result;
      };
      console.log(`${ts()}   ✓ JsonConvert.SerializeObject`);
    } catch (e) {}

    try {
      jsonConvert.method("DeserializeObject").implementation = function (...args: any[]) {
        const json = safeString(args[0]);
        log("json", "DeserializeObject", preview(json, 60));
        return this.method("DeserializeObject").invoke(...args);
      };
      console.log(`${ts()}   ✓ JsonConvert.DeserializeObject`);
    } catch (e) {}
  } catch (e) {}

  try {
    const simpleJson = asm.class("SimpleJson.SimpleJson");

    try {
      simpleJson.method("SerializeObject").implementation = function (...args: any[]) {
        const result = this.method("SerializeObject").invoke(...args);
        const json = safeString(result);
        log("json", "SimpleJson.Serialize", preview(json, 60));
        return result;
      };
      console.log(`${ts()}   ✓ SimpleJson.SerializeObject`);
    } catch (e) {}

    try {
      simpleJson.method("DeserializeObject").implementation = function (...args: any[]) {
        const json = safeString(args[0]);
        log("json", "SimpleJson.Deserialize", preview(json, 60));
        return this.method("DeserializeObject").invoke(...args);
      };
      console.log(`${ts()}   ✓ SimpleJson.DeserializeObject`);
    } catch (e) {}
  } catch (e) {}
}

function hookStreams(): void {
  console.log(`${ts()} [HOOK] Streams...`);

  try {
    const mscorlib = Il2Cpp.domain.assembly("mscorlib").image;
    const streamReader = mscorlib.class("System.IO.StreamReader");

    try {
      streamReader.method("ReadToEnd").implementation = function () {
        const result = this.method("ReadToEnd").invoke();
        const content = safeString(result);
        log("stream", "StreamReader.ReadToEnd", preview(content, 50));
        return result;
      };
      console.log(`${ts()}   ✓ StreamReader.ReadToEnd`);
    } catch (e) {}
  } catch (e) {}
}

// =============================================================================
// AUTH HOOKS
// =============================================================================

function hookLoginPackets(asm: Il2Cpp.Image): void {
  console.log(`${ts()} [HOOK] Login packets...`);

  const packetClasses = [
    "GameProtocol.CUserLoginPacket",
    "GameProtocol.CRespUserLoginPacket",
    "GameProtocol.CHeartBeatPacket",
    "GameProtocol.CRespHeartBeatPacket",
    "GameProtocol.CSyncUserPacket",
    "GameProtocol.CRespSyncUserPacket",
  ];

  for (const fullName of packetClasses) {
    try {
      const clazz = asm.class(fullName);
      const name = fullName.split(".").pop()!;

      try {
        clazz.method("WriteToStream").implementation = function (writer: any) {
          const fields = dumpAllFields(this);

          console.log(`\n${ts()} ┌─────────────────────────────────────────────────`);
          console.log(`${ts()} │ 📤 PACKET OUT: ${name}`);
          console.log(`${ts()} ├─────────────────────────────────────────────────`);
          printFields(fields);
          console.log(`${ts()} └─────────────────────────────────────────────────\n`);

          if (name === "CUserLoginPacket") loginPacketSent = true;

          packetCaptures.push({ t: elapsed(), dir: "C→S", name, fields });
          events.push({ t: elapsed(), category: "packet", op: "C→S", target: name, fields });

          return this.method("WriteToStream").invoke(writer);
        };
        console.log(`${ts()}   ✓ ${name}.WriteToStream`);
      } catch (e) {}

      try {
        clazz.method("ReadFromStream").implementation = function (reader: any) {
          const result = this.method("ReadFromStream").invoke(reader);
          const fields = dumpAllFields(this);

          console.log(`\n${ts()} ┌─────────────────────────────────────────────────`);
          console.log(`${ts()} │ 📥 PACKET IN: ${name}`);
          console.log(`${ts()} ├─────────────────────────────────────────────────`);
          printFields(fields);
          console.log(`${ts()} └─────────────────────────────────────────────────\n`);

          if (name === "CRespUserLoginPacket") loginResponseReceived = true;

          packetCaptures.push({ t: elapsed(), dir: "S→C", name, fields });
          events.push({ t: elapsed(), category: "packet", op: "S→C", target: name, fields });

          return result;
        };
        console.log(`${ts()}   ✓ ${name}.ReadFromStream`);
      } catch (e) {}
    } catch (e) {}
  }
}

function hookNetworkLayer(asm: Il2Cpp.Image): void {
  console.log(`${ts()} [HOOK] Network layer...`);

  try {
    const netManager = asm.class("Dxx.Net.NetManager");

    netManager.methods.forEach((method) => {
      if (["Connect", "Send", "Init", "Request"].some((p) => method.name.includes(p))) {
        try {
          netManager.method(method.name).implementation = function (...args: any[]) {
            const argStrs = args.map((a) => safeString(a));
            log("net", `NetManager.${method.name}`, argStrs.join(", "));
            return this.method(method.name).invoke(...args);
          };
        } catch (e) {}
      }
    });
    console.log(`${ts()}   ✓ NetManager`);
  } catch (e) {}
}

function hookTcpNetManager(asm: Il2Cpp.Image): void {
  console.log(`${ts()} [HOOK] TcpNetManager...`);

  try {
    const tcpNetMgr = asm.class("TcpNetManager");

    try {
      tcpNetMgr.method("SendPacket").implementation = function (packet: any, msgId: any) {
        const packetType = packet && packet.class ? packet.class.name : "unknown";
        log("net", "TcpNetManager.SendPacket", `msgId=${msgId} → ${packetType}`);
        return this.method("SendPacket").invoke(packet, msgId);
      };
      console.log(`${ts()}   ✓ TcpNetManager.SendPacket`);
    } catch (e) {}

    try {
      tcpNetMgr.method("SendBuffer").implementation = function (buffer: any) {
        const len = buffer ? buffer.length : 0;
        log("net", "TcpNetManager.SendBuffer", `${len} bytes`);
        return this.method("SendBuffer").invoke(buffer);
      };
      console.log(`${ts()}   ✓ TcpNetManager.SendBuffer`);
    } catch (e) {}
  } catch (e) {}
}

function hookEncryption(asm: Il2Cpp.Image): void {
  console.log(`${ts()} [HOOK] Encryption...`);

  try {
    const netEncrypt = asm.class("NetEncrypt");

    const encryptMethods = ["Encrypt_UTF8", "DesEncrypt", "DesDecrypt"];
    for (const m of encryptMethods) {
      try {
        netEncrypt.method(m).implementation = function (...args: any[]) {
          const input = args.length > 0 ? safeString(args[0]) : "";
          const result = this.method(m).invoke(...args);
          const output = safeString(result);

          log("crypto", `NetEncrypt.${m}`, preview(input, 40), preview(output, 40));
          encryptionEvents.push({
            t: elapsed(),
            method: m,
            input: input.substring(0, 100),
            output: output.substring(0, 100),
          });

          return result;
        };
        console.log(`${ts()}   ✓ NetEncrypt.${m}`);
      } catch (e) {}
    }
  } catch (e) {}

  try {
    const rc4 = asm.class("RC4Encrypter");

    try {
      rc4.method(".ctor").implementation = function (key: any) {
        const keyStr = safeString(key);
        log("crypto", "RC4Encrypter.init", preview(keyStr, 32));
        encryptionEvents.push({ t: elapsed(), method: "RC4_init", input: keyStr, output: "" });
        return this.method(".ctor").invoke(key);
      };
      console.log(`${ts()}   ✓ RC4Encrypter.ctor`);
    } catch (e) {}
  } catch (e) {}
}

// =============================================================================
// SUMMARY
// =============================================================================

function printSummary(): void {
  const totalTime = elapsed();

  console.log("\n\n");
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║               COMBINED DISCOVERY SUMMARY                     ║");
  console.log("╚══════════════════════════════════════════════════════════════╝");

  console.log(`\n📊 Session Statistics:`);
  console.log(`   Duration: ${totalTime.toFixed(1)}s`);
  console.log(`   Total events: ${events.length}`);
  console.log(`   Login sent: ${loginPacketSent ? "✓" : "✗"}`);
  console.log(`   Login response: ${loginResponseReceived ? "✓" : "✗"}`);

  // Categories
  const categories = [
    "file",
    "prefs",
    "json",
    "save",
    "crypto",
    "packet",
    "net",
    "dns",
    "asset",
    "stream",
  ];
  console.log(`\n📈 Events by Category:`);
  for (const cat of categories) {
    const count = events.filter((e) => e.category === cat).length;
    if (count > 0) console.log(`   ${cat.padEnd(8)}: ${count}`);
  }

  console.log(`\n🌐 DNS Lookups (${dnsLookups.size}):`);
  dnsLookups.forEach((ips, host) => console.log(`   - ${host}`));

  console.log(`\n🔌 TCP Connections (${connections.length}):`);
  connections
    .slice(0, 10)
    .forEach((c) => console.log(`   - ${c.ip}:${c.port} @ ${c.t.toFixed(2)}s`));

  console.log(`\n🔐 Encryption Events (${encryptionEvents.length}):`);
  encryptionEvents
    .slice(0, 10)
    .forEach((e) =>
      console.log(`   - [${e.t.toFixed(2)}s] ${e.method}: ${e.input.substring(0, 30)}...`)
    );

  console.log(`\n📡 Packets Captured (${packetCaptures.length}):`);
  packetCaptures.forEach((p) => console.log(`   - [${p.t.toFixed(2)}s] ${p.dir} ${p.name}`));

  console.log(`\n🔑 PlayerPrefs Keys (${prefsKeys.length}):`);
  prefsKeys.slice(0, 20).forEach((k) => console.log(`   - ${k}`));
  if (prefsKeys.length > 20) console.log(`   ... and ${prefsKeys.length - 20} more`);

  console.log(`\n💿 Save Data Events (${saveDataEvents.length}):`);
  const saveGroups = saveDataEvents.reduce(
    (acc, e) => {
      acc[e] = (acc[e] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );
  Object.entries(saveGroups).forEach(([k, v]) => console.log(`   - ${k}: ${v}x`));

  console.log(`\n📅 Timeline (first 50 events):`);
  console.log("─".repeat(66));
  for (const e of events.slice(0, 50)) {
    const cat = e.category.padEnd(7);
    const target = e.target.length > 40 ? "..." + e.target.slice(-37) : e.target;
    console.log(`   [${e.t.toFixed(2)}s] [${cat}] ${e.op}: ${target}`);
  }
  if (events.length > 50) console.log(`   ... and ${events.length - 50} more`);

  console.log(`\n📋 JSON Summary:`);
  console.log("─".repeat(66));
  const summary = {
    session: {
      duration: totalTime,
      totalEvents: events.length,
      loginSent: loginPacketSent,
      loginReceived: loginResponseReceived,
    },
    categories: Object.fromEntries(
      categories.map((c) => [c, events.filter((e) => e.category === c).length])
    ),
    dns: Array.from(dnsLookups.keys()),
    connections: connections.slice(0, 10),
    packets: packetCaptures.map((p) => ({ t: p.t, dir: p.dir, name: p.name })),
    encryption: encryptionEvents
      .slice(0, 20)
      .map((e) => ({ t: e.t, method: e.method, input: e.input.substring(0, 50) })),
    prefsKeys: prefsKeys.slice(0, 30),
    saveEvents: saveGroups,
  };
  console.log(JSON.stringify(summary, null, 2));

  console.log("\n" + "═".repeat(66));
}

// =============================================================================
// MAIN
// =============================================================================

hookNativeIO();
hookNativeNetwork();
hookIl2Cpp();
