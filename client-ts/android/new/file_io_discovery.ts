/**
 * File I/O Discovery Tool - Android
 *
 * Discovers all file read/write operations during the first 10 seconds
 * of app launch. Hooks native libc, System.IO, PlayerPrefs, and Unity paths.
 *
 * Usage:
 *   cd client-ts
 *   bun run file-io-discovery
 *
 * Or manually:
 *   bun run build:file-io-discovery
 *   frida -U -f com.habby.archero -l android/build/file_io_discovery.js
 */

/// <reference path="../../frida.d.ts" />

import "frida-il2cpp-bridge";

console.log("╔══════════════════════════════════════════════════════════════╗");
console.log("║     ARCHERO FILE I/O DISCOVERY (Android)                     ║");
console.log("║     Capturing first 10 seconds of file operations            ║");
console.log("╚══════════════════════════════════════════════════════════════╝");

// =============================================================================
// CONFIGURATION
// =============================================================================

const DISCOVERY_DURATION_MS = 10000;
const LOG_FILE_CONTENTS = true;
const MAX_CONTENT_PREVIEW = 256;

// Filter paths to focus on game-relevant files
const INTERESTING_PATH_PATTERNS = [
  "/data/",
  "shared_prefs",
  ".json",
  ".dat",
  ".xml",
  ".bin",
  ".save",
  "PlayerPrefs",
  "archero",
  "habby",
];

// Ignore noisy system paths
const IGNORE_PATH_PATTERNS = [
  "/proc/",
  "/sys/",
  "/dev/",
  "libfrida",
  "frida-agent",
  ".so",
  ".dex",
  ".odex",
  ".vdex",
  ".art",
];

// =============================================================================
// DATA STRUCTURES
// =============================================================================

interface FileOperation {
  t: number;
  op: "open" | "read" | "write" | "close" | "prefs_get" | "prefs_set" | "file_api";
  path: string;
  size?: number;
  flags?: string;
  preview?: string;
  method?: string;
  value?: any;
}

const fileOperations: FileOperation[] = [];
const openFds = new Map<number, string>(); // fd -> path mapping
const pathStats = new Map<string, { reads: number; writes: number; opens: number }>();

let discoveryStartTime = 0;

// =============================================================================
// HELPERS
// =============================================================================

function elapsed(): number {
  return (Date.now() - discoveryStartTime) / 1000;
}

function ts(): string {
  return `[${elapsed().toFixed(2)}s]`;
}

function isInterestingPath(path: string): boolean {
  if (!path) return false;
  
  // Check ignore patterns first
  for (const pattern of IGNORE_PATH_PATTERNS) {
    if (path.includes(pattern)) return false;
  }
  
  // Check if any interesting pattern matches
  for (const pattern of INTERESTING_PATH_PATTERNS) {
    if (path.toLowerCase().includes(pattern.toLowerCase())) return true;
  }
  
  return false;
}

function getOpenFlags(flags: number): string {
  const flagNames: string[] = [];
  if ((flags & 0x0000) === 0) flagNames.push("O_RDONLY");
  if (flags & 0x0001) flagNames.push("O_WRONLY");
  if (flags & 0x0002) flagNames.push("O_RDWR");
  if (flags & 0x0040) flagNames.push("O_CREAT");
  if (flags & 0x0200) flagNames.push("O_TRUNC");
  if (flags & 0x0400) flagNames.push("O_APPEND");
  return flagNames.join("|") || "0";
}

function updatePathStats(path: string, op: "read" | "write" | "open"): void {
  if (!pathStats.has(path)) {
    pathStats.set(path, { reads: 0, writes: 0, opens: 0 });
  }
  const stats = pathStats.get(path)!;
  if (op === "read") stats.reads++;
  if (op === "write") stats.writes++;
  if (op === "open") stats.opens++;
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

// =============================================================================
// NATIVE HOOKS: libc file operations
// =============================================================================

function hookNativeFileIO(): void {
  console.log("[NATIVE] Setting up file I/O hooks...");
  
  // Hook open()
  const openPtr = Module.findExportByName(null, "open");
  if (openPtr) {
    Interceptor.attach(openPtr, {
      onEnter(args) {
        this.path = args[0].readUtf8String();
        this.flags = args[1].toInt32();
      },
      onLeave(retval) {
        const fd = retval.toInt32();
        if (fd >= 0 && this.path && isInterestingPath(this.path)) {
          openFds.set(fd, this.path);
          updatePathStats(this.path, "open");
          
          const flagStr = getOpenFlags(this.flags);
          console.log(`${ts()} [OPEN] fd=${fd} flags=${flagStr}`);
          console.log(`${ts()}   📂 ${this.path}`);
          
          fileOperations.push({
            t: elapsed(),
            op: "open",
            path: this.path,
            flags: flagStr,
          });
        }
      }
    });
    console.log("   ✓ open() hooked");
  }
  
  // Hook openat()
  const openatPtr = Module.findExportByName(null, "openat");
  if (openatPtr) {
    Interceptor.attach(openatPtr, {
      onEnter(args) {
        this.path = args[1].readUtf8String();
        this.flags = args[2].toInt32();
      },
      onLeave(retval) {
        const fd = retval.toInt32();
        if (fd >= 0 && this.path && isInterestingPath(this.path)) {
          openFds.set(fd, this.path);
          updatePathStats(this.path, "open");
          
          const flagStr = getOpenFlags(this.flags);
          console.log(`${ts()} [OPENAT] fd=${fd} flags=${flagStr}`);
          console.log(`${ts()}   📂 ${this.path}`);
          
          fileOperations.push({
            t: elapsed(),
            op: "open",
            path: this.path,
            flags: flagStr,
          });
        }
      }
    });
    console.log("   ✓ openat() hooked");
  }
  
  // Hook read()
  const readPtr = Module.findExportByName(null, "read");
  if (readPtr) {
    Interceptor.attach(readPtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.count = args[2].toInt32();
      },
      onLeave(retval) {
        const bytesRead = retval.toInt32();
        const path = openFds.get(this.fd);
        
        if (bytesRead > 0 && path) {
          updatePathStats(path, "read");
          
          let preview = "";
          if (LOG_FILE_CONTENTS && bytesRead > 0) {
            try {
              const previewLen = Math.min(bytesRead, MAX_CONTENT_PREVIEW);
              const bytes = this.buf.readByteArray(previewLen);
              if (bytes) {
                // Try to display as text if printable
                const arr = new Uint8Array(bytes);
                let isPrintable = true;
                for (let i = 0; i < Math.min(arr.length, 32); i++) {
                  if (arr[i] < 32 && arr[i] !== 10 && arr[i] !== 13 && arr[i] !== 9) {
                    isPrintable = false;
                    break;
                  }
                }
                if (isPrintable) {
                  preview = new TextDecoder().decode(arr).substring(0, 100);
                } else {
                  // Hex preview
                  preview = Array.from(arr.slice(0, 32))
                    .map(b => b.toString(16).padStart(2, "0"))
                    .join(" ");
                }
              }
            } catch (e) {}
          }
          
          console.log(`${ts()} [READ] fd=${this.fd} ${bytesRead} bytes`);
          console.log(`${ts()}   📖 ${path}`);
          if (preview) {
            console.log(`${ts()}   📄 ${preview}${bytesRead > MAX_CONTENT_PREVIEW ? "..." : ""}`);
          }
          
          fileOperations.push({
            t: elapsed(),
            op: "read",
            path,
            size: bytesRead,
            preview: preview.substring(0, 50),
          });
        }
      }
    });
    console.log("   ✓ read() hooked");
  }
  
  // Hook write()
  const writePtr = Module.findExportByName(null, "write");
  if (writePtr) {
    Interceptor.attach(writePtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.count = args[2].toInt32();
      },
      onLeave(retval) {
        const bytesWritten = retval.toInt32();
        const path = openFds.get(this.fd);
        
        if (bytesWritten > 0 && path) {
          updatePathStats(path, "write");
          
          let preview = "";
          if (LOG_FILE_CONTENTS && this.count > 0) {
            try {
              const previewLen = Math.min(this.count, MAX_CONTENT_PREVIEW);
              const bytes = this.buf.readByteArray(previewLen);
              if (bytes) {
                const arr = new Uint8Array(bytes);
                let isPrintable = true;
                for (let i = 0; i < Math.min(arr.length, 32); i++) {
                  if (arr[i] < 32 && arr[i] !== 10 && arr[i] !== 13 && arr[i] !== 9) {
                    isPrintable = false;
                    break;
                  }
                }
                if (isPrintable) {
                  preview = new TextDecoder().decode(arr).substring(0, 100);
                } else {
                  preview = Array.from(arr.slice(0, 32))
                    .map(b => b.toString(16).padStart(2, "0"))
                    .join(" ");
                }
              }
            } catch (e) {}
          }
          
          console.log(`${ts()} [WRITE] fd=${this.fd} ${bytesWritten} bytes`);
          console.log(`${ts()}   📝 ${path}`);
          if (preview) {
            console.log(`${ts()}   📄 ${preview}${this.count > MAX_CONTENT_PREVIEW ? "..." : ""}`);
          }
          
          fileOperations.push({
            t: elapsed(),
            op: "write",
            path,
            size: bytesWritten,
            preview: preview.substring(0, 50),
          });
        }
      }
    });
    console.log("   ✓ write() hooked");
  }
  
  // Hook close()
  const closePtr = Module.findExportByName(null, "close");
  if (closePtr) {
    Interceptor.attach(closePtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
      },
      onLeave(retval) {
        const path = openFds.get(this.fd);
        if (path) {
          console.log(`${ts()} [CLOSE] fd=${this.fd}`);
          console.log(`${ts()}   📁 ${path}`);
          
          fileOperations.push({
            t: elapsed(),
            op: "close",
            path,
          });
          
          openFds.delete(this.fd);
        }
      }
    });
    console.log("   ✓ close() hooked");
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
    
    hookSystemIO();
    hookPlayerPrefs();
    hookPlayerPrefsEncrypt();
    hookUnityPaths();
    
    console.log(`\n${ts()} [READY] All hooks installed. Capturing for ${DISCOVERY_DURATION_MS / 1000}s...`);
    console.log("═".repeat(66));
    
    setTimeout(() => {
      printSummary();
    }, DISCOVERY_DURATION_MS);
  });
}

// =============================================================================
// HOOK: System.IO
// =============================================================================

function hookSystemIO(): void {
  console.log(`${ts()} [HOOK] System.IO...`);
  
  try {
    const mscorlib = Il2Cpp.domain.assembly("mscorlib").image;
    
    // System.IO.File
    try {
      const fileClass = mscorlib.class("System.IO.File");
      
      const fileMethods = ["OpenRead", "ReadAllText", "WriteAllBytes", "Create", "Delete", "Exists", "Copy", "Move"];
      for (const methodName of fileMethods) {
        try {
          fileClass.method(methodName).implementation = function(...args: any[]) {
            const path = args.length > 0 ? safeString(args[0]) : "";
            console.log(`${ts()} [FILE] System.IO.File.${methodName}`);
            console.log(`${ts()}   📂 ${path}`);
            
            fileOperations.push({
              t: elapsed(),
              op: "file_api",
              path,
              method: `File.${methodName}`,
            });
            
            return this.method(methodName).invoke(...args);
          };
          console.log(`${ts()}   ✓ File.${methodName}`);
        } catch (e) {}
      }
    } catch (e) {}
    
    // System.IO.FileStream constructor
    try {
      const fileStreamClass = mscorlib.class("System.IO.FileStream");
      
      try {
        fileStreamClass.method(".ctor").implementation = function(...args: any[]) {
          const path = args.length > 0 ? safeString(args[0]) : "";
          console.log(`${ts()} [STREAM] new FileStream`);
          console.log(`${ts()}   📂 ${path}`);
          
          fileOperations.push({
            t: elapsed(),
            op: "file_api",
            path,
            method: "FileStream.ctor",
          });
          
          return this.method(".ctor").invoke(...args);
        };
        console.log(`${ts()}   ✓ FileStream.ctor`);
      } catch (e) {}
    } catch (e) {}
    
  } catch (e) {
    console.log(`${ts()}   ✗ System.IO hooks failed: ${e}`);
  }
}

// =============================================================================
// HOOK: UnityEngine.PlayerPrefs
// =============================================================================

function hookPlayerPrefs(): void {
  console.log(`${ts()} [HOOK] UnityEngine.PlayerPrefs...`);
  
  try {
    const unityAsm = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image;
    const playerPrefs = unityAsm.class("UnityEngine.PlayerPrefs");
    
    // Get methods
    const getMethods = ["GetString", "GetInt", "GetFloat"];
    for (const methodName of getMethods) {
      try {
        playerPrefs.method(methodName).implementation = function(...args: any[]) {
          const key = args.length > 0 ? safeString(args[0]) : "";
          const result = this.method(methodName).invoke(...args);
          const value = safeString(result);
          
          console.log(`${ts()} [PREFS:GET] PlayerPrefs.${methodName}`);
          console.log(`${ts()}   🔑 ${key} = ${value.substring(0, 50)}${value.length > 50 ? "..." : ""}`);
          
          fileOperations.push({
            t: elapsed(),
            op: "prefs_get",
            path: `PlayerPrefs.${key}`,
            method: methodName,
            value: value.substring(0, 100),
          });
          
          return result;
        };
        console.log(`${ts()}   ✓ PlayerPrefs.${methodName}`);
      } catch (e) {}
    }
    
    // Set methods
    const setMethods = ["SetString", "SetInt", "SetFloat"];
    for (const methodName of setMethods) {
      try {
        playerPrefs.method(methodName).implementation = function(...args: any[]) {
          const key = args.length > 0 ? safeString(args[0]) : "";
          const value = args.length > 1 ? safeString(args[1]) : "";
          
          console.log(`${ts()} [PREFS:SET] PlayerPrefs.${methodName}`);
          console.log(`${ts()}   🔑 ${key} = ${value.substring(0, 50)}${value.length > 50 ? "..." : ""}`);
          
          fileOperations.push({
            t: elapsed(),
            op: "prefs_set",
            path: `PlayerPrefs.${key}`,
            method: methodName,
            value: value.substring(0, 100),
          });
          
          return this.method(methodName).invoke(...args);
        };
        console.log(`${ts()}   ✓ PlayerPrefs.${methodName}`);
      } catch (e) {}
    }
    
    // Save
    try {
      playerPrefs.method("Save").implementation = function() {
        console.log(`${ts()} [PREFS:SAVE] PlayerPrefs.Save()`);
        
        fileOperations.push({
          t: elapsed(),
          op: "prefs_set",
          path: "PlayerPrefs.Save",
          method: "Save",
        });
        
        return this.method("Save").invoke();
      };
      console.log(`${ts()}   ✓ PlayerPrefs.Save`);
    } catch (e) {}
    
  } catch (e) {
    console.log(`${ts()}   ✗ PlayerPrefs hooks failed: ${e}`);
  }
}

// =============================================================================
// HOOK: PlayerPrefsEncrypt
// =============================================================================

function hookPlayerPrefsEncrypt(): void {
  console.log(`${ts()} [HOOK] PlayerPrefsEncrypt...`);
  
  try {
    const asm = Il2Cpp.domain.assembly("Assembly-CSharp").image;
    const prefsEncrypt = asm.class("PlayerPrefsEncrypt");
    
    // Get methods
    const getMethods = ["GetString", "GetInt", "GetBool", "GetLong", "GetFloat"];
    for (const methodName of getMethods) {
      try {
        prefsEncrypt.method(methodName).implementation = function(...args: any[]) {
          const key = args.length > 0 ? safeString(args[0]) : "";
          const result = this.method(methodName).invoke(...args);
          const value = safeString(result);
          
          console.log(`${ts()} [PREFS:GET:ENC] PlayerPrefsEncrypt.${methodName}`);
          console.log(`${ts()}   🔐 ${key} = ${value.substring(0, 50)}${value.length > 50 ? "..." : ""}`);
          
          fileOperations.push({
            t: elapsed(),
            op: "prefs_get",
            path: `PlayerPrefsEncrypt.${key}`,
            method: methodName,
            value: value.substring(0, 100),
          });
          
          return result;
        };
        console.log(`${ts()}   ✓ PlayerPrefsEncrypt.${methodName}`);
      } catch (e) {}
    }
    
    // Set methods
    const setMethods = ["SetString", "SetInt", "SetBool", "SetLong", "SetFloat"];
    for (const methodName of setMethods) {
      try {
        prefsEncrypt.method(methodName).implementation = function(...args: any[]) {
          const key = args.length > 0 ? safeString(args[0]) : "";
          const value = args.length > 1 ? safeString(args[1]) : "";
          
          console.log(`${ts()} [PREFS:SET:ENC] PlayerPrefsEncrypt.${methodName}`);
          console.log(`${ts()}   🔐 ${key} = ${value.substring(0, 50)}${value.length > 50 ? "..." : ""}`);
          
          fileOperations.push({
            t: elapsed(),
            op: "prefs_set",
            path: `PlayerPrefsEncrypt.${key}`,
            method: methodName,
            value: value.substring(0, 100),
          });
          
          return this.method(methodName).invoke(...args);
        };
        console.log(`${ts()}   ✓ PlayerPrefsEncrypt.${methodName}`);
      } catch (e) {}
    }
    
    // Encrypt method
    try {
      prefsEncrypt.method("Encrypt").implementation = function(...args: any[]) {
        const input = args.length > 0 ? safeString(args[0]) : "";
        const result = this.method("Encrypt").invoke(...args);
        const output = safeString(result);
        
        console.log(`${ts()} [CRYPTO] PlayerPrefsEncrypt.Encrypt`);
        console.log(`${ts()}   IN:  ${input.substring(0, 40)}${input.length > 40 ? "..." : ""}`);
        console.log(`${ts()}   OUT: ${output.substring(0, 40)}${output.length > 40 ? "..." : ""}`);
        
        return result;
      };
      console.log(`${ts()}   ✓ PlayerPrefsEncrypt.Encrypt`);
    } catch (e) {}
    
  } catch (e) {
    console.log(`${ts()}   ✗ PlayerPrefsEncrypt hooks failed: ${e}`);
  }
}

// =============================================================================
// HOOK: Unity Application paths
// =============================================================================

function hookUnityPaths(): void {
  console.log(`${ts()} [HOOK] Unity Application paths...`);
  
  try {
    const unityAsm = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image;
    const application = unityAsm.class("UnityEngine.Application");
    
    try {
      application.method("get_persistentDataPath").implementation = function() {
        const result = this.method("get_persistentDataPath").invoke();
        const path = safeString(result);
        console.log(`${ts()} [PATH] Application.persistentDataPath = ${path}`);
        return result;
      };
      console.log(`${ts()}   ✓ Application.get_persistentDataPath`);
    } catch (e) {}
    
    try {
      application.method("get_dataPath").implementation = function() {
        const result = this.method("get_dataPath").invoke();
        const path = safeString(result);
        console.log(`${ts()} [PATH] Application.dataPath = ${path}`);
        return result;
      };
      console.log(`${ts()}   ✓ Application.get_dataPath`);
    } catch (e) {}
    
    try {
      application.method("get_temporaryCachePath").implementation = function() {
        const result = this.method("get_temporaryCachePath").invoke();
        const path = safeString(result);
        console.log(`${ts()} [PATH] Application.temporaryCachePath = ${path}`);
        return result;
      };
      console.log(`${ts()}   ✓ Application.get_temporaryCachePath`);
    } catch (e) {}
    
  } catch (e) {
    console.log(`${ts()}   ✗ Unity path hooks failed: ${e}`);
  }
}

// =============================================================================
// SUMMARY
// =============================================================================

function printSummary(): void {
  const totalTime = elapsed();
  
  console.log("\n");
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║               FILE I/O DISCOVERY SUMMARY                     ║");
  console.log("╚══════════════════════════════════════════════════════════════╝");
  
  console.log(`\n📊 Session Statistics:`);
  console.log(`   Duration: ${totalTime.toFixed(1)}s`);
  console.log(`   Total operations: ${fileOperations.length}`);
  console.log(`   Unique paths: ${pathStats.size}`);
  
  // Operation breakdown
  const opCounts = {
    open: fileOperations.filter(o => o.op === "open").length,
    read: fileOperations.filter(o => o.op === "read").length,
    write: fileOperations.filter(o => o.op === "write").length,
    close: fileOperations.filter(o => o.op === "close").length,
    prefs_get: fileOperations.filter(o => o.op === "prefs_get").length,
    prefs_set: fileOperations.filter(o => o.op === "prefs_set").length,
    file_api: fileOperations.filter(o => o.op === "file_api").length,
  };
  
  console.log(`\n📈 Operation Breakdown:`);
  console.log(`   Opens:     ${opCounts.open}`);
  console.log(`   Reads:     ${opCounts.read}`);
  console.log(`   Writes:    ${opCounts.write}`);
  console.log(`   Closes:    ${opCounts.close}`);
  console.log(`   Prefs Get: ${opCounts.prefs_get}`);
  console.log(`   Prefs Set: ${opCounts.prefs_set}`);
  console.log(`   File API:  ${opCounts.file_api}`);
  
  console.log(`\n📁 Files Accessed (by frequency):`);
  console.log("─".repeat(66));
  const sortedPaths = Array.from(pathStats.entries())
    .sort((a, b) => (b[1].opens + b[1].reads + b[1].writes) - (a[1].opens + a[1].reads + a[1].writes))
    .slice(0, 30);
  
  for (const [path, stats] of sortedPaths) {
    const total = stats.opens + stats.reads + stats.writes;
    const shortPath = path.length > 50 ? "..." + path.slice(-47) : path;
    console.log(`   [${total.toString().padStart(3)}] O:${stats.opens} R:${stats.reads} W:${stats.writes} | ${shortPath}`);
  }
  
  console.log(`\n📅 Timeline (first 30 operations):`);
  console.log("─".repeat(66));
  for (const op of fileOperations.slice(0, 30)) {
    const opIcon = op.op === "read" ? "📖" : op.op === "write" ? "📝" : op.op === "open" ? "📂" : "📁";
    const shortPath = op.path.length > 40 ? "..." + op.path.slice(-37) : op.path;
    const sizeStr = op.size ? ` (${op.size}B)` : "";
    console.log(`   [${op.t.toFixed(2)}s] ${opIcon} ${op.op.padEnd(10)} ${shortPath}${sizeStr}`);
  }
  if (fileOperations.length > 30) {
    console.log(`   ... and ${fileOperations.length - 30} more operations`);
  }
  
  console.log(`\n📋 JSON Summary:`);
  console.log("─".repeat(66));
  const summary = {
    session: { duration: totalTime, totalOps: fileOperations.length, uniquePaths: pathStats.size },
    operationCounts: opCounts,
    topPaths: sortedPaths.slice(0, 15).map(([path, stats]) => ({ path, ...stats })),
    operations: fileOperations.slice(0, 50).map(o => ({
      t: o.t,
      op: o.op,
      path: o.path.length > 60 ? "..." + o.path.slice(-57) : o.path,
      size: o.size,
    })),
  };
  console.log(JSON.stringify(summary, null, 2));
  
  console.log("\n" + "═".repeat(66));
}

// =============================================================================
// MAIN
// =============================================================================

hookNativeFileIO();
hookIl2Cpp();
