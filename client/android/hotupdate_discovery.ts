/**
 * Hot Update Discovery Tool
 *
 * A focused discovery agent that hooks all classes related to the hot update
 * system (https://hotupdate-archero.habby.com) to document the update protocol
 * during the first 20 seconds of app launch.
 *
 * Output: Writes structured log files to logs/sessions/ directory.
 *
 * Usage:
 *   bun run build:hotupdate-discovery
 *   adb shell am force-stop com.habby.archero
 *   adb shell monkey -p com.habby.archero -c android.intent.category.LAUNCHER 1
 *   sleep 3
 *   frida -U -N com.habby.archero -l android/build/hotupdate_discovery.js 2>&1 | tee logs/sessions/hotupdate_$(date +%Y%m%d_%H%M%S).log
 */

import "frida-il2cpp-bridge";

console.log("[HotUpdateDiscovery] Script loaded");

const DISCOVERY_DURATION_MS = 20000; // 20 seconds

// =============================================================================
// DATA STORAGE
// =============================================================================

interface MethodCall {
  t: number;      // timestamp (seconds)
  c: string;      // className
  m: string;      // methodName
  a: string[];    // args
  r?: string;     // returnValue
}

const methodCalls: MethodCall[] = [];
const hookedClasses: Map<string, number> = new Map(); // className -> method count
let discoveryStartTime = 0;

// Store captured URLs and headers
const capturedURLs: Set<string> = new Set();
const capturedHeaders: Map<string, string> = new Map();

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

function getElapsedSeconds(): number {
  return (Date.now() - discoveryStartTime) / 1000;
}

function formatTimestamp(): string {
  return getElapsedSeconds().toFixed(2);
}

// Convert Il2Cpp value to readable string
function formatValue(value: any): string {
  if (value === null || value === undefined) {
    return "<null>";
  }

  try {
    // Check if it's an Il2Cpp.String
    if (value.class?.name === "String") {
      const content = value.content;
      if (content) {
        // Capture URLs containing hotupdate
        if (content.includes("hotupdate") || content.includes("archero")) {
          capturedURLs.add(content);
        }
        return `"${content}"`;
      }
      return "<empty string>";
    }

    // Check if it's a byte array
    if (value.class?.name === "Byte[]") {
      const len = value.length ?? 0;
      if (len === 0) return "<empty bytes>";

      const bytes: number[] = [];
      const maxShow = Math.min(len, 128);
      for (let i = 0; i < maxShow; i++) {
        bytes.push(value.get_Item(i) & 0xff);
      }
      return len > maxShow ? `[${bytes.join(",")} ...(+${len - maxShow})]` : `[${bytes.join(",")}]`;
    }

    // Check if has meaningful toString
    const str = String(value);
    if (str.length > 300) {
      return str.substring(0, 300) + "...";
    }
    return str;
  } catch (e) {
    return "<unreadable>";
  }
}

// Format method arguments
function formatArgs(args: any[]): string[] {
  return args.map((arg) => formatValue(arg));
}

// Log a method call
function logMethodCall(
  className: string,
  methodName: string,
  args: any[],
  returnValue?: any
) {
  const formattedArgs = formatArgs(args);
  const formattedReturn = returnValue !== undefined ? formatValue(returnValue) : undefined;

  const call: MethodCall = {
    t: Math.round(getElapsedSeconds() * 100) / 100,
    c: className,
    m: methodName,
    a: formattedArgs,
    r: formattedReturn,
  };
  methodCalls.push(call);

  // Console output
  const argsStr = formattedArgs.length > 0 ? `: ${formattedArgs.join(", ")}` : "";
  console.log(`[${formatTimestamp()}s][${className}::${methodName}]${argsStr}`);
  if (formattedReturn && formattedReturn !== "<null>") {
    console.log(`  => ${formattedReturn}`);
  }
}

// =============================================================================
// CLASS HOOKING
// =============================================================================

const IGNORED_METHODS = [
  "Finalize", ".cctor", ".ctor", "ToString", "GetHashCode", "Equals",
  "get_IsDisposed", "Dispose",
];

function hookClass(
  className: string,
  clazz: Il2Cpp.Class,
  ignoredMethods: string[] = []
): number {
  const allIgnored = [...IGNORED_METHODS, ...ignoredMethods];
  let hookedCount = 0;

  clazz.methods.forEach((method) => {
    if (allIgnored.includes(method.name)) return;
    if (method.name.startsWith("get_") && method.parameterCount === 0) return;

    try {
      clazz.method(method.name).implementation = function (this: any, ...args: any[]) {
        const result = this.method(method.name).invoke(...args);
        logMethodCall(className, method.name, args, result);
        return result;
      };
      hookedCount++;
    } catch (e) {
      // Silent fail for methods that can't be hooked
    }
  });

  if (hookedCount > 0) {
    hookedClasses.set(className, hookedCount);
    console.log(`[HotUpdateDiscovery] Hooked ${hookedCount} methods on ${className}`);
  }

  return hookedCount;
}

function tryHookClass(
  assembly: Il2Cpp.Image,
  className: string,
  ignoredMethods: string[] = []
): boolean {
  try {
    const clazz = assembly.class(className);
    hookClass(className, clazz, ignoredMethods);
    return true;
  } catch (e) {
    console.log(`[HotUpdateDiscovery] Class "${className}" not found`);
    return false;
  }
}

// Hook by searching for classes containing a keyword
function hookClassesContaining(
  assembly: Il2Cpp.Image,
  keyword: string,
  ignoredMethods: string[] = []
): number {
  let totalHooked = 0;
  try {
    assembly.classes.forEach((clazz) => {
      const fullName = clazz.namespace ? `${clazz.namespace}.${clazz.name}` : clazz.name;
      if (fullName.toLowerCase().includes(keyword.toLowerCase())) {
        try {
          const count = hookClass(fullName, clazz, ignoredMethods);
          if (count > 0) totalHooked++;
        } catch (e) {
          // Skip failed hooks
        }
      }
    });
  } catch (e) {
    console.log(`[HotUpdateDiscovery] Error searching for "${keyword}": ${e}`);
  }
  return totalHooked;
}

// =============================================================================
// ASSEMBLY ENUMERATION
// =============================================================================

function loadAssembly(name: string): Il2Cpp.Image | null {
  try {
    return Il2Cpp.domain.assembly(name).image;
  } catch (e) {
    return null;
  }
}

// =============================================================================
// LOG OUTPUT
// =============================================================================

function generateLogOutput(): {
  summary: string;
  fullLog: object;
} {
  const elapsed = getElapsedSeconds();

  // Count method frequencies
  const methodFreq: Map<string, number> = new Map();
  for (const call of methodCalls) {
    const key = `${call.c}::${call.m}`;
    methodFreq.set(key, (methodFreq.get(key) || 0) + 1);
  }
  const sortedMethods = [...methodFreq.entries()].sort((a, b) => b[1] - a[1]);

  // Group by class
  const classCalls: Map<string, MethodCall[]> = new Map();
  for (const call of methodCalls) {
    const existing = classCalls.get(call.c) || [];
    existing.push(call);
    classCalls.set(call.c, existing);
  }

  // Generate summary text
  const lines: string[] = [];
  lines.push("=".repeat(70));
  lines.push("   HOT UPDATE DISCOVERY SESSION SUMMARY");
  lines.push("=".repeat(70));
  lines.push(`Session Duration: ${elapsed.toFixed(1)}s`);
  lines.push(`Total Method Calls: ${methodCalls.length}`);
  lines.push(`Unique Methods: ${methodFreq.size}`);
  lines.push(`Hooked Classes: ${hookedClasses.size}`);
  lines.push("");

  lines.push("--- CAPTURED URLs ---");
  for (const url of capturedURLs) {
    lines.push(`  ${url}`);
  }
  lines.push("");

  lines.push("--- METHOD FREQUENCY (top 50) ---");
  for (const [method, count] of sortedMethods.slice(0, 50)) {
    lines.push(`  ${count.toString().padStart(4)}x  ${method}`);
  }
  lines.push("");

  lines.push("--- HOOKED CLASSES ---");
  const sortedClasses = [...hookedClasses.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  for (const [className, methodCount] of sortedClasses) {
    const callCount = classCalls.get(className)?.length || 0;
    lines.push(`  ${className}: ${methodCount} methods hooked, ${callCount} calls`);
  }
  lines.push("");

  lines.push("--- SANDBOX RECONSTRUCTION GUIDE ---");
  lines.push("To reconstruct the hot update server for sandbox:");
  lines.push("");
  lines.push("1. HOT UPDATE ENDPOINT:");
  lines.push("   - Base URL: https://hotupdate-archero.habby.com");
  const updateURLs = [...capturedURLs].filter(u => u.includes("hotupdate"));
  for (const url of updateURLs) {
    lines.push(`   - ${url}`);
  }
  lines.push("");

  lines.push("2. VERSION CHECK FLOW:");
  const versionCalls = methodCalls.filter(c => 
    c.m.toLowerCase().includes("version") || 
    c.c.toLowerCase().includes("version") ||
    c.c.toLowerCase().includes("update")
  );
  if (versionCalls.length > 0) {
    lines.push(`   - Found ${versionCalls.length} version/update related calls`);
    const versionMethods = new Set(versionCalls.map(c => `${c.c}::${c.m}`));
    for (const m of versionMethods) {
      lines.push(`     - ${m}`);
    }
  }
  lines.push("");

  lines.push("3. ASSET BUNDLE OPERATIONS:");
  const assetCalls = methodCalls.filter(c => 
    c.c.toLowerCase().includes("asset") || 
    c.c.toLowerCase().includes("bundle") ||
    c.m.toLowerCase().includes("download")
  );
  if (assetCalls.length > 0) {
    lines.push(`   - Found ${assetCalls.length} asset/bundle related calls`);
    const assetMethods = new Set(assetCalls.map(c => `${c.c}::${c.m}`));
    for (const m of assetMethods) {
      lines.push(`     - ${m}`);
    }
  }
  lines.push("");

  lines.push("4. HTTP OPERATIONS:");
  const httpCalls = methodCalls.filter(c => 
    c.c.toLowerCase().includes("http") || 
    c.c.toLowerCase().includes("webrequest") ||
    c.c.toLowerCase().includes("download")
  );
  if (httpCalls.length > 0) {
    lines.push(`   - Found ${httpCalls.length} HTTP-related calls`);
  }
  lines.push("");

  lines.push("5. KEY METHODS TO IMPLEMENT:");
  const importantMethods = methodCalls
    .filter(c => 
      c.m.toLowerCase().includes("check") ||
      c.m.toLowerCase().includes("download") ||
      c.m.toLowerCase().includes("update") ||
      c.m.toLowerCase().includes("load") ||
      c.m.toLowerCase().includes("get")
    )
    .map(c => `${c.c}::${c.m}`);
  const uniqueImportant = [...new Set(importantMethods)].slice(0, 20);
  for (const m of uniqueImportant) {
    const count = methodFreq.get(m) || 0;
    lines.push(`   - ${m}: ${count} calls`);
  }
  lines.push("");
  lines.push("=".repeat(70));

  // Full log object
  const fullLog = {
    session: {
      duration: elapsed,
      timestamp: new Date().toISOString(),
      totalCalls: methodCalls.length,
      uniqueMethods: methodFreq.size,
      hookedClasses: Object.fromEntries(hookedClasses),
    },
    capturedURLs: [...capturedURLs],
    methodFrequency: Object.fromEntries(sortedMethods),
    calls: methodCalls,
  };

  return { summary: lines.join("\n"), fullLog };
}

function printAndDumpLogs() {
  const { summary, fullLog } = generateLogOutput();

  // Print summary to console
  console.log("\n" + summary);

  // Dump full log as JSON for file saving
  console.log("\n--- FULL LOG (JSON) ---");
  console.log("HOTUPDATE_DISCOVERY_LOG_START");
  console.log(JSON.stringify(fullLog, null, 2));
  console.log("HOTUPDATE_DISCOVERY_LOG_END");

  // Print instructions
  console.log("\n[HotUpdateDiscovery] To save logs, run:");
  console.log("  frida ... | tee logs/sessions/hotupdate_discovery_$(date +%Y%m%d_%H%M%S).log");
}

// =============================================================================
// MAIN DISCOVERY LOGIC
// =============================================================================

console.log(`[HotUpdateDiscovery] Will discover for ${DISCOVERY_DURATION_MS / 1000}s...`);

Il2Cpp.perform(() => {
  discoveryStartTime = Date.now();
  console.log("[HotUpdateDiscovery] Il2Cpp runtime ready, starting discovery...");

  // Load assemblies
  const assemblies = {
    CSharp: loadAssembly("Assembly-CSharp"),
    HabbyUpdate: loadAssembly("HabbyUpdateLib"),
    HabbyTool: loadAssembly("HabbyToolLib"),
    Lib: loadAssembly("lib"),
    MsCorLib: loadAssembly("mscorlib"),
    UnityWebRequest: loadAssembly("UnityEngine.UnityWebRequestModule"),
    UnityAssetBundle: loadAssembly("UnityEngine.AssetBundleModule"),
    UnityCore: loadAssembly("UnityEngine.CoreModule"),
  };

  console.log("\n[HotUpdateDiscovery] === HOOKING UPDATE CLASSES ===");
  
  // Try to hook HabbyUpdateLib classes
  if (assemblies.HabbyUpdate) {
    console.log("[HotUpdateDiscovery] Found HabbyUpdateLib!");
    hookClassesContaining(assemblies.HabbyUpdate, "Update");
    hookClassesContaining(assemblies.HabbyUpdate, "Version");
    hookClassesContaining(assemblies.HabbyUpdate, "Hot");
    hookClassesContaining(assemblies.HabbyUpdate, "Download");
    hookClassesContaining(assemblies.HabbyUpdate, "Asset");
  }

  // Hook classes in Assembly-CSharp related to updates
  if (assemblies.CSharp) {
    console.log("[HotUpdateDiscovery] Hooking Assembly-CSharp update classes...");
    
    // Hook update-related classes
    hookClassesContaining(assemblies.CSharp, "HotUpdate", ["Update"]);
    hookClassesContaining(assemblies.CSharp, "Version", ["Update"]);
    hookClassesContaining(assemblies.CSharp, "AssetBundle", ["Update"]);
    hookClassesContaining(assemblies.CSharp, "Download", ["Update"]);
    hookClassesContaining(assemblies.CSharp, "Patch", ["Update"]);
    hookClassesContaining(assemblies.CSharp, "Resource", ["Update"]);
    
    // Also hook HTTP and network classes for update requests
    tryHookClass(assemblies.CSharp, "HTTPSendClient", [
      "isTimeOut", "get_timeout", "get_starttime", "check_done", "get_IsCache",
    ]);
    tryHookClass(assemblies.CSharp, "Dxx.Net.NetConfig");
    tryHookClass(assemblies.CSharp, "NetEncrypt");
  }

  // Hook HabbyToolLib for utility methods
  if (assemblies.HabbyTool) {
    hookClassesContaining(assemblies.HabbyTool, "Http");
    hookClassesContaining(assemblies.HabbyTool, "Download");
    hookClassesContaining(assemblies.HabbyTool, "Update");
  }

  // Hook Unity networking
  if (assemblies.UnityWebRequest) {
    tryHookClass(assemblies.UnityWebRequest, "UnityEngine.Networking.UnityWebRequest", [
      "get_isDone", "get_timeout", "get_error", "Abort",
    ]);
    tryHookClass(assemblies.UnityWebRequest, "UnityEngine.Networking.DownloadHandler", [
      "get_data",
    ]);
    tryHookClass(assemblies.UnityWebRequest, "UnityEngine.Networking.DownloadHandlerBuffer");
    tryHookClass(assemblies.UnityWebRequest, "UnityEngine.Networking.DownloadHandlerAssetBundle");
  }

  // Hook AssetBundle classes
  if (assemblies.UnityAssetBundle) {
    tryHookClass(assemblies.UnityAssetBundle, "UnityEngine.AssetBundle", ["Unload"]);
    tryHookClass(assemblies.UnityAssetBundle, "UnityEngine.AssetBundleCreateRequest");
    tryHookClass(assemblies.UnityAssetBundle, "UnityEngine.AssetBundleRequest");
  }

  // Hook core Unity for WWW (legacy) if exists
  if (assemblies.UnityCore) {
    tryHookClass(assemblies.UnityCore, "UnityEngine.WWW");
    tryHookClass(assemblies.UnityCore, "UnityEngine.Application", ["Update"]);
  }

  console.log(`\n[HotUpdateDiscovery] ${hookedClasses.size} classes hooked`);
  console.log(`[HotUpdateDiscovery] Monitoring for ${DISCOVERY_DURATION_MS / 1000} seconds...\n`);

  setTimeout(() => {
    console.log("\n[HotUpdateDiscovery] Discovery period complete!");
    printAndDumpLogs();
  }, DISCOVERY_DURATION_MS);
});
