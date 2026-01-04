/**
 * Storage Discovery Tool - Android
 *
 * Discovers all storage operations (files, prefs, cache, assets, serialization)
 * during the first 15 seconds of app launch.
 *
 * Usage:
 *   cd client-ts
 *   bun run storage-discovery
 *
 * Or manually:
 *   bun run build:storage-discovery
 *   frida -U -f com.habby.archero -l android/build/storage_discovery.js
 */

/// <reference path="../../frida.d.ts" />

import "frida-il2cpp-bridge";

console.log("╔══════════════════════════════════════════════════════════════╗");
console.log("║     ARCHERO STORAGE DISCOVERY (Android)                      ║");
console.log("║     Capturing first 15 seconds of storage operations         ║");
console.log("╚══════════════════════════════════════════════════════════════╝");

// =============================================================================
// CONFIGURATION
// =============================================================================

const DISCOVERY_DURATION_MS = 15000;
const LOG_CONTENT_PREVIEW = true;
const MAX_PREVIEW_LEN = 128;

const INTERESTING_PATHS = ["/data/", "shared_prefs", ".json", ".dat", ".xml", ".bin", ".save", "archero", "habby"];
const IGNORE_PATHS = ["/proc/", "/sys/", "/dev/", "libfrida", ".so", ".dex", ".odex"];

// =============================================================================
// DATA STRUCTURES
// =============================================================================

interface StorageOperation {
  t: number;
  category: "file" | "prefs" | "asset" | "json" | "binary" | "stream" | "save";
  op: string;
  target: string;
  detail?: string;
  value?: string;
}

const operations: StorageOperation[] = [];
const openFds = new Map<number, string>();
const assetBundles: string[] = [];
const prefsKeys: string[] = [];
const saveDataEvents: string[] = [];

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
  const icon = {
    file: "📂", prefs: "🔑", asset: "📦", json: "📋", binary: "💾", stream: "📖", save: "💿"
  }[category] || "📁";
  
  console.log(`${ts()} [${category.toUpperCase().padEnd(6)}] ${icon} ${op}: ${preview(target, 50)}`);
  if (detail) console.log(`${ts()}   └─ ${preview(detail, 80)}`);
  
  operations.push({
    t: elapsed(),
    category: category as StorageOperation["category"],
    op,
    target: target.substring(0, 200),
    detail: detail?.substring(0, 100),
  });
}

// =============================================================================
// NATIVE HOOKS
// =============================================================================

function hookNativeIO(): void {
  console.log("[NATIVE] Setting up file I/O hooks...");
  
  try {
    const openPtr = Module.findExportByName(null, "open");
    if (openPtr) {
      Interceptor.attach(openPtr, {
        onEnter(args) { 
          try { this.path = args[0].readUtf8String(); } catch(e) { this.path = null; }
        },
        onLeave(retval) {
          try {
            const fd = retval.toInt32();
            if (fd >= 0 && this.path && isInteresting(this.path)) {
              openFds.set(fd, this.path);
              log("file", "open", this.path);
            }
          } catch(e) {}
        }
      });
      console.log("   ✓ open()");
    }
    
    const openatPtr = Module.findExportByName(null, "openat");
    if (openatPtr) {
      Interceptor.attach(openatPtr, {
        onEnter(args) {
          try { this.path = args[1].readUtf8String(); } catch(e) { this.path = null; }
        },
        onLeave(retval) {
          try {
            const fd = retval.toInt32();
            if (fd >= 0 && this.path && isInteresting(this.path)) {
              openFds.set(fd, this.path);
              log("file", "openat", this.path);
            }
          } catch(e) {}
        }
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
          } catch(e) { this.fd = -1; }
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
                  if (arr) preview = Array.from(new Uint8Array(arr)).map(b => b.toString(16).padStart(2, "0")).join(" ");
                } catch (e) {}
              }
              log("file", `read(${bytes}B)`, path, preview);
            }
          } catch(e) {}
        }
      });
      console.log("   ✓ read()");
    }
    
    const writePtr = Module.findExportByName(null, "write");
    if (writePtr) {
      Interceptor.attach(writePtr, {
        onEnter(args) { 
          try {
            this.fd = args[0].toInt32(); 
            this.buf = args[1]; 
            this.count = args[2].toInt32(); 
          } catch(e) { this.fd = -1; }
        },
        onLeave(retval) {
          try {
            const bytes = retval.toInt32();
            const path = openFds.get(this.fd);
            if (bytes > 0 && path) {
              log("file", `write(${bytes}B)`, path);
            }
          } catch(e) {}
        }
      });
      console.log("   ✓ write()");
    }
    
    const closePtr = Module.findExportByName(null, "close");
    if (closePtr) {
      Interceptor.attach(closePtr, {
        onEnter(args) { 
          try { this.fd = args[0].toInt32(); } catch(e) { this.fd = -1; }
        },
        onLeave() { 
          try { openFds.delete(this.fd); } catch(e) {}
        }
      });
      console.log("   ✓ close()");
    }
  } catch (e) {
    console.log(`   ✗ Native hooks failed: ${e}`);
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
    hookUnityPaths();
    hookLocalSave();
    hookPlayerPrefs();
    hookSharedPreferences();
    hookAssetLoading();
    hookJsonSerialization();
    hookBinarySerialization();
    hookStreams();
    
    console.log(`\n${ts()} [READY] All hooks installed. Capturing for ${DISCOVERY_DURATION_MS / 1000}s...`);
    console.log("═".repeat(66));
    
    setTimeout(() => printSummary(), DISCOVERY_DURATION_MS);
  });
}

// =============================================================================
// HOOK: System.IO.File and FileStream
// =============================================================================

function hookSystemIO(): void {
  console.log(`${ts()} [HOOK] System.IO...`);
  
  try {
    const mscorlib = Il2Cpp.domain.assembly("mscorlib").image;
    
    // System.IO.File
    try {
      const fileClass = mscorlib.class("System.IO.File");
      const fileMethods = ["OpenRead", "ReadAllText", "WriteAllBytes", "Create", "Delete", "Exists", "Copy", "Move"];
      for (const m of fileMethods) {
        try {
          fileClass.method(m).implementation = function(...args: any[]) {
            const path = args.length > 0 ? safeString(args[0]) : "";
            log("file", `File.${m}`, path);
            return this.method(m).invoke(...args);
          };
          console.log(`${ts()}   ✓ File.${m}`);
        } catch (e) {}
      }
    } catch (e) {}
    
    // System.IO.FileStream constructor
    try {
      const fileStreamClass = mscorlib.class("System.IO.FileStream");
      fileStreamClass.method(".ctor").implementation = function(...args: any[]) {
        const path = args.length > 0 ? safeString(args[0]) : "";
        log("file", "FileStream.ctor", path);
        return this.method(".ctor").invoke(...args);
      };
      console.log(`${ts()}   ✓ FileStream.ctor`);
    } catch (e) {}
  } catch (e) {
    console.log(`${ts()}   ✗ System.IO hooks failed`);
  }
}

// =============================================================================
// HOOK: Unity Application Paths
// =============================================================================

function hookUnityPaths(): void {
  console.log(`${ts()} [HOOK] Unity paths...`);
  
  try {
    const unityAsm = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image;
    const application = unityAsm.class("UnityEngine.Application");
    
    try {
      application.method("get_persistentDataPath").implementation = function() {
        const result = this.method("get_persistentDataPath").invoke();
        const path = safeString(result);
        log("file", "persistentDataPath", path);
        return result;
      };
      console.log(`${ts()}   ✓ Application.persistentDataPath`);
    } catch (e) {}
    
    try {
      application.method("get_dataPath").implementation = function() {
        const result = this.method("get_dataPath").invoke();
        const path = safeString(result);
        log("file", "dataPath", path);
        return result;
      };
      console.log(`${ts()}   ✓ Application.dataPath`);
    } catch (e) {}
    
    try {
      application.method("get_temporaryCachePath").implementation = function() {
        const result = this.method("get_temporaryCachePath").invoke();
        const path = safeString(result);
        log("file", "temporaryCachePath", path);
        return result;
      };
      console.log(`${ts()}   ✓ Application.temporaryCachePath`);
    } catch (e) {}
  } catch (e) {
    console.log(`${ts()}   ✗ Unity path hooks failed`);
  }
}

// =============================================================================
// HOOK: LocalSave
// =============================================================================

function hookLocalSave(): void {
  console.log(`${ts()} [HOOK] LocalSave...`);
  
  try {
    const asm = Il2Cpp.domain.assembly("Assembly-CSharp").image;
    
    // LocalSave.InitSaveData
    try {
      const localSave = asm.class("LocalSave");
      localSave.method("InitSaveData").implementation = function() {
        log("save", "InitSaveData", "LocalSave");
        saveDataEvents.push("InitSaveData");
        return this.method("InitSaveData").invoke();
      };
      console.log(`${ts()}   ✓ LocalSave.InitSaveData`);
    } catch (e) {}
    
    // LocalSave.SaveDataRefresh
    try {
      const localSave = asm.class("LocalSave");
      localSave.method("SaveDataRefresh").implementation = function() {
        log("save", "SaveDataRefresh", "LocalSave");
        saveDataEvents.push("SaveDataRefresh");
        return this.method("SaveDataRefresh").invoke();
      };
      console.log(`${ts()}   ✓ LocalSave.SaveDataRefresh`);
    } catch (e) {}
    
    // LocalSaveBase.SaveData
    try {
      const localSaveBase = asm.class("LocalSaveBase");
      localSaveBase.method("SaveData").implementation = function() {
        log("save", "SaveData", "LocalSaveBase");
        saveDataEvents.push("LocalSaveBase.SaveData");
        return this.method("SaveData").invoke();
      };
      console.log(`${ts()}   ✓ LocalSaveBase.SaveData`);
    } catch (e) {}
    
    // LocalSave.SaveData.serializeObject
    try {
      const saveData = asm.class("LocalSave.SaveData");
      saveData.method("serializeObject").implementation = function() {
        log("save", "serializeObject", "LocalSave.SaveData");
        return this.method("serializeObject").invoke();
      };
      console.log(`${ts()}   ✓ LocalSave.SaveData.serializeObject`);
    } catch (e) {}
    
  } catch (e) {
    console.log(`${ts()}   ✗ LocalSave hooks failed: ${e}`);
  }
}

// =============================================================================
// HOOK: PlayerPrefs
// =============================================================================

function hookPlayerPrefs(): void {
  console.log(`${ts()} [HOOK] PlayerPrefs...`);
  
  // PlayerPrefsMgr.PrefDataBase
  try {
    const asm = Il2Cpp.domain.assembly("Assembly-CSharp").image;
    const prefDataBase = asm.class("PlayerPrefsMgr.PrefDataBase");
    
    try {
      prefDataBase.method("flush").implementation = function() {
        const name = safeString(this.field("name").value);
        log("prefs", "flush", `PrefDataBase.${name}`);
        return this.method("flush").invoke();
      };
      console.log(`${ts()}   ✓ PrefDataBase.flush`);
    } catch (e) {}
    
    try {
      prefDataBase.method("Delete").implementation = function() {
        const name = safeString(this.field("name").value);
        log("prefs", "Delete", `PrefDataBase.${name}`);
        return this.method("Delete").invoke();
      };
      console.log(`${ts()}   ✓ PrefDataBase.Delete`);
    } catch (e) {}
  } catch (e) {}
  
  // PlayerPrefsEncrypt
  try {
    const asm = Il2Cpp.domain.assembly("Assembly-CSharp").image;
    const prefsEncrypt = asm.class("PlayerPrefsEncrypt");
    
    const getMethods = ["GetString", "GetInt", "GetBool", "GetLong", "GetFloat"];
    for (const m of getMethods) {
      try {
        prefsEncrypt.method(m).implementation = function(...args: any[]) {
          const key = safeString(args[0]);
          const result = this.method(m).invoke(...args);
          const value = safeString(result);
          log("prefs", `${m}`, key, value);
          if (!prefsKeys.includes(key)) prefsKeys.push(key);
          return result;
        };
        console.log(`${ts()}   ✓ PlayerPrefsEncrypt.${m}`);
      } catch (e) {}
    }
    
    const setMethods = ["SetString", "SetInt", "SetBool", "SetLong", "SetFloat"];
    for (const m of setMethods) {
      try {
        prefsEncrypt.method(m).implementation = function(...args: any[]) {
          const key = safeString(args[0]);
          const value = args.length > 1 ? safeString(args[1]) : "";
          log("prefs", `${m}`, key, value);
          if (!prefsKeys.includes(key)) prefsKeys.push(key);
          return this.method(m).invoke(...args);
        };
        console.log(`${ts()}   ✓ PlayerPrefsEncrypt.${m}`);
      } catch (e) {}
    }
  } catch (e) {}
}

// =============================================================================
// HOOK: Android SharedPreferences
// =============================================================================

function hookSharedPreferences(): void {
  console.log(`${ts()} [HOOK] SharedPreferences...`);
  
  try {
    const unityServices = Il2Cpp.domain.assembly("Unity.Services.Core").image;
    const androidUtils = unityServices.class("Unity.Services.Core.Device.AndroidUtils");
    
    try {
      androidUtils.method("SharedPreferencesGetString").implementation = function(...args: any[]) {
        const key = safeString(args[1]);
        const result = this.method("SharedPreferencesGetString").invoke(...args);
        const value = safeString(result);
        log("prefs", "SharedPrefs.Get", key, value);
        return result;
      };
      console.log(`${ts()}   ✓ AndroidUtils.SharedPreferencesGetString`);
    } catch (e) {}
    
    try {
      androidUtils.method("SharedPreferencesPutString").implementation = function(...args: any[]) {
        const key = safeString(args[1]);
        const value = safeString(args[2]);
        log("prefs", "SharedPrefs.Put", key, value);
        return this.method("SharedPreferencesPutString").invoke(...args);
      };
      console.log(`${ts()}   ✓ AndroidUtils.SharedPreferencesPutString`);
    } catch (e) {}
  } catch (e) {
    console.log(`${ts()}   ✗ SharedPreferences not found`);
  }
}

// =============================================================================
// HOOK: Asset Loading
// =============================================================================

function hookAssetLoading(): void {
  console.log(`${ts()} [HOOK] Asset loading...`);
  
  try {
    const asm = Il2Cpp.domain.assembly("Assembly-CSharp").image;
    
    // ResourceManager.GetAssetBundle
    try {
      const resourceMgr = asm.class("ResourceManager");
      resourceMgr.method("GetAssetBundle").implementation = function(...args: any[]) {
        const name = safeString(args[0]);
        log("asset", "GetAssetBundle", name);
        if (!assetBundles.includes(name)) assetBundles.push(name);
        return this.method("GetAssetBundle").invoke(...args);
      };
      console.log(`${ts()}   ✓ ResourceManager.GetAssetBundle`);
    } catch (e) {}
    
    // AddressableManager loading
    try {
      const addressable = asm.class("Dxx.Addressable.AddressableManager");
      
      addressable.methods.forEach(method => {
        if (method.name.includes("LoadAsset") || method.name.includes("LoadScene")) {
          try {
            addressable.method(method.name).implementation = function(...args: any[]) {
              const asset = args.length > 0 ? safeString(args[0]) : "";
              log("asset", method.name, asset);
              return this.method(method.name).invoke(...args);
            };
          } catch (e) {}
        }
      });
      console.log(`${ts()}   ✓ AddressableManager`);
    } catch (e) {}
    
  } catch (e) {
    console.log(`${ts()}   ✗ Asset loading hooks failed`);
  }
}

// =============================================================================
// HOOK: JSON Serialization
// =============================================================================

function hookJsonSerialization(): void {
  console.log(`${ts()} [HOOK] JSON serialization...`);
  
  // Newtonsoft.Json
  try {
    const newtonsoftAsm = Il2Cpp.domain.assembly("Newtonsoft.Json").image;
    const jsonConvert = newtonsoftAsm.class("Newtonsoft.Json.JsonConvert");
    
    try {
      jsonConvert.method("SerializeObject").implementation = function(...args: any[]) {
        const result = this.method("SerializeObject").invoke(...args);
        const json = safeString(result);
        log("json", "SerializeObject", preview(json, 60));
        return result;
      };
      console.log(`${ts()}   ✓ JsonConvert.SerializeObject`);
    } catch (e) {}
    
    try {
      jsonConvert.method("DeserializeObject").implementation = function(...args: any[]) {
        const json = safeString(args[0]);
        log("json", "DeserializeObject", preview(json, 60));
        return this.method("DeserializeObject").invoke(...args);
      };
      console.log(`${ts()}   ✓ JsonConvert.DeserializeObject`);
    } catch (e) {}
  } catch (e) {}
  
  // SimpleJson
  try {
    const asm = Il2Cpp.domain.assembly("Assembly-CSharp").image;
    const simpleJson = asm.class("SimpleJson.SimpleJson");
    
    try {
      simpleJson.method("SerializeObject").implementation = function(...args: any[]) {
        const result = this.method("SerializeObject").invoke(...args);
        const json = safeString(result);
        log("json", "SimpleJson.Serialize", preview(json, 60));
        return result;
      };
      console.log(`${ts()}   ✓ SimpleJson.SerializeObject`);
    } catch (e) {}
    
    try {
      simpleJson.method("DeserializeObject").implementation = function(...args: any[]) {
        const json = safeString(args[0]);
        log("json", "SimpleJson.Deserialize", preview(json, 60));
        return this.method("DeserializeObject").invoke(...args);
      };
      console.log(`${ts()}   ✓ SimpleJson.DeserializeObject`);
    } catch (e) {}
  } catch (e) {}
}

// =============================================================================
// HOOK: Binary Serialization
// =============================================================================

function hookBinarySerialization(): void {
  console.log(`${ts()} [HOOK] Binary serialization...`);
  
  try {
    const mscorlib = Il2Cpp.domain.assembly("mscorlib").image;
    const binaryFormatter = mscorlib.class("System.Runtime.Serialization.Formatters.Binary.BinaryFormatter");
    
    try {
      binaryFormatter.method("Serialize").implementation = function(...args: any[]) {
        log("binary", "BinaryFormatter.Serialize", "stream");
        return this.method("Serialize").invoke(...args);
      };
      console.log(`${ts()}   ✓ BinaryFormatter.Serialize`);
    } catch (e) {}
    
    try {
      binaryFormatter.method("Deserialize").implementation = function(...args: any[]) {
        const result = this.method("Deserialize").invoke(...args);
        let typeName = "unknown";
        try {
          const r = result as any;
          if (r && r.class) typeName = r.class.name || "unknown";
        } catch (e) {}
        log("binary", "BinaryFormatter.Deserialize", typeName);
        return result;
      };
      console.log(`${ts()}   ✓ BinaryFormatter.Deserialize`);
    } catch (e) {}
  } catch (e) {
    console.log(`${ts()}   ✗ BinaryFormatter hooks failed`);
  }
}

// =============================================================================
// HOOK: Streams
// =============================================================================

function hookStreams(): void {
  console.log(`${ts()} [HOOK] Streams...`);
  
  try {
    const mscorlib = Il2Cpp.domain.assembly("mscorlib").image;
    
    // StreamReader
    try {
      const streamReader = mscorlib.class("System.IO.StreamReader");
      
      try {
        streamReader.method("ReadToEnd").implementation = function() {
          const result = this.method("ReadToEnd").invoke();
          const content = safeString(result);
          log("stream", "StreamReader.ReadToEnd", preview(content, 50));
          return result;
        };
        console.log(`${ts()}   ✓ StreamReader.ReadToEnd`);
      } catch (e) {}
      
      try {
        streamReader.method("ReadLine").implementation = function() {
          const result = this.method("ReadLine").invoke();
          const line = safeString(result);
          if (line !== "<null>") log("stream", "StreamReader.ReadLine", preview(line, 50));
          return result;
        };
        console.log(`${ts()}   ✓ StreamReader.ReadLine`);
      } catch (e) {}
    } catch (e) {}
    
    // StreamWriter
    try {
      const streamWriter = mscorlib.class("System.IO.StreamWriter");
      
      try {
        streamWriter.method("Write").implementation = function(...args: any[]) {
          const content = safeString(args[0]);
          log("stream", "StreamWriter.Write", preview(content, 50));
          return this.method("Write").invoke(...args);
        };
        console.log(`${ts()}   ✓ StreamWriter.Write`);
      } catch (e) {}
      
      try {
        streamWriter.method("WriteLine").implementation = function(...args: any[]) {
          const content = safeString(args[0]);
          log("stream", "StreamWriter.WriteLine", preview(content, 50));
          return this.method("WriteLine").invoke(...args);
        };
        console.log(`${ts()}   ✓ StreamWriter.WriteLine`);
      } catch (e) {}
    } catch (e) {}
  } catch (e) {
    console.log(`${ts()}   ✗ Stream hooks failed`);
  }
}

// =============================================================================
// SUMMARY
// =============================================================================

function printSummary(): void {
  const totalTime = elapsed();
  
  console.log("\n");
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║               STORAGE DISCOVERY SUMMARY                      ║");
  console.log("╚══════════════════════════════════════════════════════════════╝");
  
  console.log(`\n📊 Session Statistics:`);
  console.log(`   Duration: ${totalTime.toFixed(1)}s`);
  console.log(`   Total operations: ${operations.length}`);
  
  // By category
  const categories = ["file", "prefs", "asset", "json", "binary", "stream", "save"];
  console.log(`\n📈 Operations by Category:`);
  for (const cat of categories) {
    const count = operations.filter(o => o.category === cat).length;
    if (count > 0) console.log(`   ${cat.padEnd(8)}: ${count}`);
  }
  
  console.log(`\n💿 Save Data Events (${saveDataEvents.length}):`);
  saveDataEvents.slice(0, 10).forEach(e => console.log(`   - ${e}`));
  
  console.log(`\n🔑 PlayerPrefs Keys Accessed (${prefsKeys.length}):`);
  prefsKeys.slice(0, 15).forEach(k => console.log(`   - ${k}`));
  if (prefsKeys.length > 15) console.log(`   ... and ${prefsKeys.length - 15} more`);
  
  console.log(`\n📦 Asset Bundles Loaded (${assetBundles.length}):`);
  assetBundles.slice(0, 10).forEach(b => console.log(`   - ${b}`));
  
  console.log(`\n📅 Timeline (first 40 operations):`);
  console.log("─".repeat(66));
  for (const op of operations.slice(0, 40)) {
    const cat = op.category.padEnd(6);
    const target = op.target.length > 40 ? "..." + op.target.slice(-37) : op.target;
    console.log(`   [${op.t.toFixed(2)}s] [${cat}] ${op.op}: ${target}`);
  }
  if (operations.length > 40) console.log(`   ... and ${operations.length - 40} more`);
  
  console.log(`\n📋 JSON Summary:`);
  console.log("─".repeat(66));
  const summary = {
    duration: totalTime,
    totalOps: operations.length,
    byCategory: Object.fromEntries(categories.map(c => [c, operations.filter(o => o.category === c).length])),
    saveEvents: saveDataEvents,
    prefsKeys: prefsKeys.slice(0, 20),
    assetBundles: assetBundles.slice(0, 10),
    timeline: operations.slice(0, 30).map(o => ({ t: o.t, cat: o.category, op: o.op, target: o.target.substring(0, 50) })),
  };
  console.log(JSON.stringify(summary, null, 2));
  
  console.log("\n" + "═".repeat(66));
}

// =============================================================================
// MAIN
// =============================================================================

hookNativeIO();
hookIl2Cpp();
