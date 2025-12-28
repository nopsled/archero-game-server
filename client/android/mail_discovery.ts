/**
 * Mail Discovery Tool
 *
 * A focused discovery agent that hooks all Habby.Mail system classes and related
 * HTTP/crypto/network classes to document the mail protocol during the first 20
 * seconds of app launch.
 *
 * Output: Writes structured log files to logs/sessions/ directory.
 *
 * Usage:
 *   bun run build:mail-discovery
 *   adb shell am force-stop com.habby.archero
 *   adb shell monkey -p com.habby.archero -c android.intent.category.LAUNCHER 1
 *   sleep 5
 *   frida -U -N com.habby.archero -l android/build/mail_discovery.js
 */

import "frida-il2cpp-bridge";

console.log("[MailDiscovery] Script loaded");

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
      return content ? `"${content}"` : "<empty string>";
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
    console.log(`[MailDiscovery] Hooked ${hookedCount} methods on ${className}`);
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
    console.log(`[MailDiscovery] Class "${className}" not found`);
    return false;
  }
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
  lines.push("=" .repeat(70));
  lines.push("   MAIL DISCOVERY SESSION SUMMARY");
  lines.push("=".repeat(70));
  lines.push(`Session Duration: ${elapsed.toFixed(1)}s`);
  lines.push(`Total Method Calls: ${methodCalls.length}`);
  lines.push(`Unique Methods: ${methodFreq.size}`);
  lines.push(`Hooked Classes: ${hookedClasses.size}`);
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
  lines.push("To reconstruct the mail server for sandbox:");
  lines.push("");
  lines.push("1. HTTP ENDPOINTS (Dxx.Net.NetConfig::GetPath):");
  const pathCalls = methodCalls.filter(c => c.m === "GetPath");
  const paths = new Set(pathCalls.map(c => c.r).filter(Boolean));
  for (const path of paths) {
    lines.push(`   - ${path}`);
  }
  lines.push("");

  lines.push("2. REQUEST SIGNING (HTTPSendClient::GetSHA256):");
  lines.push("   - Header: HabbyCheck = SHA256(HabbyApiKey + HabbyTime + requestBody)");
  lines.push("   - HabbyApiKey appears to be: A63B6DBE18D84CA29887198B4ACBDEE9");
  lines.push("   - HabbyTime = Unix timestamp");
  lines.push("   - Response header: Habby (value varies)");
  lines.push("");

  lines.push("3. ENCRYPTION:");
  const rc4Calls = methodCalls.filter(c => c.c === "RC4Encrypter");
  const netEncCalls = methodCalls.filter(c => c.c === "NetEncrypt");
  lines.push(`   - RC4Encrypter: ${rc4Calls.length} calls`);
  lines.push(`   - NetEncrypt: ${netEncCalls.length} calls`);
  lines.push("   - Key: 4ptjerlkgjlk34jylkej4rgklj4klyj (from NetEncrypt::Encrypt_UTF8)");
  lines.push("");

  lines.push("4. KEY METHODS TO IMPLEMENT:");
  const importantMethods = [
    "Dxx.Net.NetConfig::GetPath",
    "HTTPSendClient::sendInternal",
    "HTTPSendClient::GetSHA256",
    "NetEncrypt::Encrypt_UTF8",
    "RC4Encrypter::Encrypt",
    "UnityEngine.Networking.UnityWebRequest::Put",
    "UnityEngine.Networking.UnityWebRequest::SetRequestHeader",
  ];
  for (const m of importantMethods) {
    const count = methodFreq.get(m) || 0;
    if (count > 0) {
      lines.push(`   - ${m}: ${count} calls`);
    }
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
  console.log("MAIL_DISCOVERY_LOG_START");
  console.log(JSON.stringify(fullLog, null, 2));
  console.log("MAIL_DISCOVERY_LOG_END");

  // Print instructions
  console.log("\n[MailDiscovery] To save logs, run:");
  console.log("  frida ... | tee logs/sessions/mail_discovery_$(date +%Y%m%d_%H%M%S).log");
}

// =============================================================================
// MAIN DISCOVERY LOGIC
// =============================================================================

console.log(`[MailDiscovery] Will discover for ${DISCOVERY_DURATION_MS / 1000}s...`);

Il2Cpp.perform(() => {
  discoveryStartTime = Date.now();
  console.log("[MailDiscovery] Il2Cpp runtime ready, starting discovery...");

  // Load assemblies
  const assemblies = {
    CSharp: loadAssembly("Assembly-CSharp"),
    HabbyMail: loadAssembly("HabbyMailLib"),
    HabbyTool: loadAssembly("HabbyToolLib"),
    Lib: loadAssembly("lib"),
    MsCorLib: loadAssembly("mscorlib"),
    UnityWebRequest: loadAssembly("UnityEngine.UnityWebRequestModule"),
  };

  console.log("\n[MailDiscovery] === HOOKING HABBY.MAIL ===");
  if (assemblies.HabbyMail) {
    tryHookClass(assemblies.HabbyMail, "Habby.Mail.HabbyMailEventDispatch");
    tryHookClass(assemblies.HabbyMail, "Habby.Mail.HabbyMailNoticeType");
    tryHookClass(assemblies.HabbyMail, "Habby.Mail.MailHttpManager");
    tryHookClass(assemblies.HabbyMail, "Habby.Mail.MailManager");
    tryHookClass(assemblies.HabbyMail, "Habby.Mail.MailRequestPath");
    tryHookClass(assemblies.HabbyMail, "Habby.Mail.MailSetting");
    tryHookClass(assemblies.HabbyMail, "Habby.Mail.StoreChannel");
  }

  console.log("\n[MailDiscovery] === HOOKING SUPPORT CLASSES ===");
  if (assemblies.CSharp) {
    tryHookClass(assemblies.CSharp, "HTTPSendClient", [
      "isTimeOut", "get_timeout", "get_starttime", "check_done", "get_IsCache",
    ]);
    tryHookClass(assemblies.CSharp, "Habby.Archero.Crypto.NetEnc");
    tryHookClass(assemblies.CSharp, "NetEncrypt");
    tryHookClass(assemblies.CSharp, "RC4Encrypter");
    tryHookClass(assemblies.CSharp, "Dxx.Net.NetConfig");
    tryHookClass(assemblies.CSharp, "TcpNetManager", ["Update"]);
  }

  if (assemblies.MsCorLib) {
    tryHookClass(assemblies.MsCorLib, "System.Security.Cryptography.SHA256");
    tryHookClass(assemblies.MsCorLib, "System.Security.Cryptography.HashAlgorithm");
  }

  if (assemblies.UnityWebRequest) {
    tryHookClass(assemblies.UnityWebRequest, "UnityEngine.Networking.UnityWebRequest", [
      "get_isDone", "get_timeout", "get_error", "Abort",
    ]);
    tryHookClass(assemblies.UnityWebRequest, "UnityEngine.Networking.DownloadHandler", [
      "get_data",
    ]);
  }

  console.log(`\n[MailDiscovery] ${hookedClasses.size} classes hooked`);
  console.log(`[MailDiscovery] Monitoring for ${DISCOVERY_DURATION_MS / 1000} seconds...\n`);

  setTimeout(() => {
    console.log("\n[MailDiscovery] Discovery period complete!");
    printAndDumpLogs();
  }, DISCOVERY_DURATION_MS);
});
