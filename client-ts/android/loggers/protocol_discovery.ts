/**
 * GameProtocol Discovery Tool
 *
 * A comprehensive discovery agent that hooks ALL classes in the GameProtocol
 * namespace to log every method call with arguments and return values.
 *
 * Output: 
 *   - Real-time console output
 *   - Structured log file in logs/sessions/
 *
 * Usage:
 *   bun run build:protocol-discovery
 *   adb shell am force-stop com.habby.archero
 *   adb shell monkey -p com.habby.archero -c android.intent.category.LAUNCHER 1
 *   sleep 5
 *   frida -U -N com.habby.archero -l android/build/protocol_discovery.js 2>&1 | tee logs/sessions/protocol_$(date +%Y%m%d_%H%M%S).log
 */

import "frida-il2cpp-bridge";

console.log("[ProtocolDiscovery] Script loaded");

const DISCOVERY_DURATION_MS = 60000; // 60 seconds for comprehensive capture

// =============================================================================
// DATA STORAGE
// =============================================================================

interface MethodCall {
  t: number;      // timestamp (seconds)
  d?: string;     // direction hint (C->S / S->C)
  c: string;      // className
  m: string;      // methodName
  a: string[];    // args
  r?: string;     // returnValue
  f?: FieldDump[]; // packet fields (for stream operations)
}

interface FieldDump {
  name: string;
  type: string;
  value: string;
}

const methodCalls: MethodCall[] = [];
const hookedClasses: Map<string, number> = new Map(); // className -> method count
const classCallCounts: Map<string, number> = new Map(); // className -> call count
let discoveryStartTime = 0;
let totalHookedMethods = 0;

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

function getElapsedSeconds(): number {
  return (Date.now() - discoveryStartTime) / 1000;
}

function formatTimestamp(): string {
  return getElapsedSeconds().toFixed(2);
}

// =============================================================================
// PACKET FIELD DUMPING
// =============================================================================

// Format field value with full detail for packet capture
function formatFieldValue(value: any, typeName: string, depth: number): string {
  if (value === null || value === undefined) {
    return "null";
  }
  
  if (depth > 3) {
    return "<nested...>";
  }
  
  try {
    // Primitives
    if (typeName === "Boolean" || typeName === "bool") {
      return value ? "true" : "false";
    }
    if (["Int32", "UInt32", "Int64", "UInt64", "Int16", "UInt16", "Byte", "SByte", "Single", "Double"].includes(typeName)) {
      return String(value);
    }
    
    // String
    if (typeName === "String" || value.class?.name === "String") {
      const content = value.content;
      if (content === null || content === undefined) return "null";
      if (content === "") return '""';
      // Escape special chars and truncate
      const escaped = content.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r');
      if (escaped.length > 500) {
        return `"${escaped.substring(0, 500)}..." (len=${content.length})`;
      }
      return `"${escaped}"`;
    }
    
    // Byte arrays - show as hex
    if (typeName === "Byte[]" || value.class?.name === "Byte[]") {
      const len = value.length ?? 0;
      if (len === 0) return "[]";
      
      const hexBytes: string[] = [];
      const maxShow = Math.min(len, 64);
      for (let i = 0; i < maxShow; i++) {
        const b = value.get_Item(i) & 0xff;
        hexBytes.push(b.toString(16).padStart(2, '0'));
      }
      const hex = hexBytes.join(' ');
      return len > maxShow 
        ? `[${hex}...] (len=${len})`
        : `[${hex}]`;
    }
    
    // Lists
    if (typeName.startsWith("List`1") || value.class?.name?.startsWith("List`1")) {
      try {
        const count = value.method("get_Count").invoke();
        if (count === 0) return "[]";
        
        const items: string[] = [];
        const maxShow = Math.min(count, 10);
        for (let i = 0; i < maxShow; i++) {
          try {
            const item = value.method("get_Item").invoke(i);
            const itemType = item?.class?.name || "unknown";
            items.push(formatFieldValue(item, itemType, depth + 1));
          } catch {
            items.push("<err>");
          }
        }
        const itemsStr = items.join(", ");
        return count > maxShow 
          ? `[${itemsStr}, ...] (count=${count})`
          : `[${itemsStr}]`;
      } catch {
        return "<list error>";
      }
    }
    
    // Nested protocol objects - recurse
    const className = value.class?.name;
    if (className && (className.startsWith("C") || className.startsWith("ST"))) {
      const nestedFields = dumpPacketFields(value);
      if (nestedFields.length === 0) {
        return `${className}{}`;
      }
      const fieldStrs = nestedFields.map(f => `${f.name}: ${f.value}`);
      if (fieldStrs.length > 5) {
        return `${className}{${fieldStrs.slice(0, 5).join(", ")}, ...}`;
      }
      return `${className}{${fieldStrs.join(", ")}}`;
    }
    
    // Fallback
    return String(value);
  } catch (e) {
    return "<error>";
  }
}

// Dump all fields from a protocol object instance
function dumpPacketFields(instance: any): FieldDump[] {
  const fields: FieldDump[] = [];
  
  try {
    instance.class.fields.forEach((field: any) => {
      if (field.isStatic) return;
      
      try {
        const fieldValue = instance.field(field.name).value;
        const typeName = field.type?.name || "unknown";
        const formattedValue = formatFieldValue(fieldValue, typeName, 0);
        
        fields.push({
          name: field.name,
          type: typeName,
          value: formattedValue,
        });
      } catch (e) {
        fields.push({
          name: field.name,
          type: field.type?.name || "unknown",
          value: "<error reading>",
        });
      }
    });
  } catch (e) {
    // Class introspection failed
  }
  
  return fields;
}

// =============================================================================
// VALUE FORMATTING
// =============================================================================

// Convert Il2Cpp value to readable string with deep inspection
function formatValue(value: any, depth: number = 0): string {
  if (value === null || value === undefined) {
    return "<null>";
  }

  if (depth > 2) {
    return "<max depth>";
  }

  try {
    const className = value.class?.name;

    // Handle String
    if (className === "String") {
      const content = value.content;
      if (content) {
        // Truncate long strings
        if (content.length > 200) {
          return `"${content.substring(0, 200)}..."`;
        }
        return `"${content}"`;
      }
      return "<empty string>";
    }

    // Handle byte arrays
    if (className === "Byte[]") {
      const len = value.length ?? 0;
      if (len === 0) return "<empty bytes>";

      const bytes: number[] = [];
      const maxShow = Math.min(len, 64);
      for (let i = 0; i < maxShow; i++) {
        bytes.push(value.get_Item(i) & 0xff);
      }
      
      // Try to decode as UTF-8 if printable
      try {
        const str = bytes.map(b => String.fromCharCode(b)).join('');
        if (/^[\x20-\x7E]+$/.test(str)) {
          return len > maxShow 
            ? `bytes[${len}]: "${str}..."`
            : `bytes[${len}]: "${str}"`;
        }
      } catch {}
      
      return len > maxShow 
        ? `[${bytes.join(",")}...(+${len - maxShow})]` 
        : `[${bytes.join(",")}]`;
    }

    // Handle arrays
    if (className?.endsWith("[]")) {
      const len = value.length ?? 0;
      if (len === 0) return `${className}[]`;
      
      const items: string[] = [];
      const maxShow = Math.min(len, 5);
      for (let i = 0; i < maxShow; i++) {
        try {
          items.push(formatValue(value.get_Item(i), depth + 1));
        } catch {
          items.push("<err>");
        }
      }
      return len > maxShow 
        ? `${className}[${len}]: [${items.join(", ")}...]`
        : `${className}[${len}]: [${items.join(", ")}]`;
    }

    // Handle List<T>
    if (className?.startsWith("List`1")) {
      try {
        const count = value.method("get_Count").invoke();
        if (count === 0) return `List<>[0]`;
        
        const items: string[] = [];
        const maxShow = Math.min(count, 3);
        for (let i = 0; i < maxShow; i++) {
          try {
            items.push(formatValue(value.method("get_Item").invoke(i), depth + 1));
          } catch {
            items.push("<err>");
          }
        }
        return count > maxShow 
          ? `List<>[${count}]: [${items.join(", ")}...]`
          : `List<>[${count}]: [${items.join(", ")}]`;
      } catch {
        return `List<>`;
      }
    }

    // Handle GameProtocol types - extract key fields
    if (className?.startsWith("C") || className?.startsWith("ST")) {
      try {
        const fields: string[] = [];
        value.class.fields.forEach((field: any) => {
          if (field.isStatic) return;
          try {
            const fieldVal = value.field(field.name).value;
            const formatted = formatValue(fieldVal, depth + 1);
            if (formatted !== "<null>" && formatted !== "<unreadable>") {
              fields.push(`${field.name}=${formatted}`);
            }
          } catch {}
        });
        if (fields.length > 0) {
          const fieldsStr = fields.slice(0, 5).join(", ");
          return fields.length > 5 
            ? `${className}{${fieldsStr}...}`
            : `${className}{${fieldsStr}}`;
        }
      } catch {}
    }

    // Check if has meaningful toString
    const str = String(value);
    if (str.length > 200) {
      return str.substring(0, 200) + "...";
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

// =============================================================================
// LOGGING
// =============================================================================

function inferDirection(methodName: string): string | undefined {
  // Heuristics based on protocol base-class naming:
  // - Write* is typically client->server serialization
  // - Read* is typically server->client deserialization
  if (methodName === "WriteToStream" || methodName === "OnWriteToStream" || methodName === "buildPacket") {
    return "C->S";
  }
  if (methodName === "ReadFromStream" || methodName === "OnReadFromStream") {
    return "S->C";
  }
  return undefined;
}

// Log a method call with optional packet dump
function logMethodCall(
  className: string,
  methodName: string,
  args: any[],
  returnValue?: any,
  packetDump?: FieldDump[]
) {
  const formattedArgs = formatArgs(args);
  const formattedReturn = returnValue !== undefined ? formatValue(returnValue) : undefined;
  const direction = inferDirection(methodName);

  // Update call counts
  classCallCounts.set(className, (classCallCounts.get(className) || 0) + 1);

  const call: MethodCall = {
    t: Math.round(getElapsedSeconds() * 100) / 100,
    d: direction,
    c: className,
    m: methodName,
    a: formattedArgs,
    r: formattedReturn,
    f: packetDump,
  };
  methodCalls.push(call);

  // Console output
  const argsStr = formattedArgs.length > 0 ? `(${formattedArgs.join(", ")})` : "()";
  console.log(
    `[${formatTimestamp()}s]${direction ? ` [${direction}]` : ""} ${className}::${methodName}${argsStr}`,
  );
  if (formattedReturn && formattedReturn !== "<null>" && formattedReturn !== "<unreadable>") {
    console.log(`  => ${formattedReturn}`);
  }
  
  // Print packet fields for stream operations
  if (packetDump && packetDump.length > 0) {
    console.log(`  [PACKET${direction ? ` ${direction}` : ""} ${className}]`);
    for (const field of packetDump) {
      // Truncate very long values in console
      let val = field.value;
      if (val.length > 200) {
        val = val.substring(0, 200) + "...";
      }
      console.log(`    ${field.name} (${field.type}): ${val}`);
    }
  }
}

// =============================================================================
// CLASS HOOKING
// =============================================================================

const IGNORED_METHODS = [
  "Finalize", ".cctor", ".ctor", "ToString", "GetHashCode", "Equals",
  "get_IsDisposed", "Dispose", "MemberwiseClone",
];

// Methods that indicate we should dump the packet fields
const STREAM_METHODS = [
  "ReadFromStream",
  "OnReadFromStream", 
  "WriteToStream",
  "OnWriteToStream",
  "buildPacket",
];

function hookClass(
  className: string,
  clazz: Il2Cpp.Class
): number {
  let hookedCount = 0;

  clazz.methods.forEach((method) => {
    if (IGNORED_METHODS.includes(method.name)) return;
    // Skip simple getters (no args)
    if (method.name.startsWith("get_") && method.parameterCount === 0) return;
    // Skip simple setters (1 arg)
    if (method.name.startsWith("set_") && method.parameterCount === 1) return;

    const isStreamMethod = STREAM_METHODS.includes(method.name);

    try {
      clazz.method(method.name).implementation = function (this: any, ...args: any[]) {
        let result: any;
        try {
          result = this.method(method.name).invoke(...args);
        } catch (e) {
          console.log(`[ERROR] ${className}::${method.name} invoke failed: ${e}`);
          throw e;
        }
        
        // For stream methods, dump the packet fields after the call
        let packetDump: FieldDump[] | undefined;
        if (isStreamMethod) {
          try {
            packetDump = dumpPacketFields(this);
          } catch (e) {
            // Field dump failed, continue without it
          }
        }
        
        logMethodCall(className, method.name, args, result, packetDump);
        return result;
      };
      hookedCount++;
    } catch (e) {
      // Silent fail for methods that can't be hooked
    }
  });

  if (hookedCount > 0) {
    hookedClasses.set(className, hookedCount);
    totalHookedMethods += hookedCount;
  }

  return hookedCount;
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
    const key = `${call.d ?? "?"} ${call.c}::${call.m}`;
    methodFreq.set(key, (methodFreq.get(key) || 0) + 1);
  }
  const sortedMethods = [...methodFreq.entries()].sort((a, b) => b[1] - a[1]);

  // Sort classes by call count
  const sortedClasses = [...classCallCounts.entries()].sort((a, b) => b[1] - a[1]);

  // Generate summary text
  const lines: string[] = [];
  lines.push("=".repeat(80));
  lines.push("   GAMEPROTOCOL DISCOVERY SESSION SUMMARY");
  lines.push("=".repeat(80));
  lines.push(`Session Duration: ${elapsed.toFixed(1)}s`);
  lines.push(`Total Method Calls: ${methodCalls.length}`);
  lines.push(`Unique Methods Called: ${methodFreq.size}`);
  lines.push(`Classes Hooked: ${hookedClasses.size}`);
  lines.push(`Total Methods Hooked: ${totalHookedMethods}`);
  lines.push(`Classes with Activity: ${classCallCounts.size}`);
  lines.push("");

  lines.push("--- MOST ACTIVE CLASSES ---");
  for (const [className, count] of sortedClasses.slice(0, 30)) {
    lines.push(`  ${count.toString().padStart(5)}x  ${className}`);
  }
  lines.push("");

  lines.push("--- METHOD FREQUENCY (top 50) ---");
  for (const [method, count] of sortedMethods.slice(0, 50)) {
    lines.push(`  ${count.toString().padStart(5)}x  ${method}`);
  }
  lines.push("");

  lines.push("--- REQUEST/RESPONSE PAIRS ---");
  const reqClasses = [...classCallCounts.keys()].filter(c => c.startsWith("CReq") || c.startsWith("STReq"));
  const respClasses = [...classCallCounts.keys()].filter(c => c.startsWith("CResp") || c.startsWith("STResp"));
  lines.push(`  Request classes active: ${reqClasses.length}`);
  for (const req of reqClasses) {
    lines.push(`    - ${req} (${classCallCounts.get(req)} calls)`);
  }
  lines.push(`  Response classes active: ${respClasses.length}`);
  for (const resp of respClasses) {
    lines.push(`    - ${resp} (${classCallCounts.get(resp)} calls)`);
  }
  lines.push("");

  lines.push("--- SANDBOX RECONSTRUCTION GUIDE ---");
  lines.push("Protocol classes represent game API request/response structures:");
  lines.push("");
  lines.push("1. REQUEST CLASSES (CReq*/STReq*):");
  lines.push("   - Constructed by client to send to server");
  lines.push("   - Fields contain request parameters");
  lines.push("");
  lines.push("2. RESPONSE CLASSES (CResp*/STResp*):");
  lines.push("   - Received from server");
  lines.push("   - Fields contain server response data");
  lines.push("");
  lines.push("3. DATA CLASSES (C*/ST* without Req/Resp):");
  lines.push("   - Nested data structures used in requests/responses");
  lines.push("");
  lines.push("=".repeat(80));

  // Full log object
  const fullLog = {
    session: {
      duration: elapsed,
      timestamp: new Date().toISOString(),
      totalCalls: methodCalls.length,
      uniqueMethods: methodFreq.size,
      hookedClasses: hookedClasses.size,
      totalHookedMethods: totalHookedMethods,
    },
    activeClasses: Object.fromEntries(sortedClasses),
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
  console.log("PROTOCOL_DISCOVERY_LOG_START");
  console.log(JSON.stringify(fullLog, null, 2));
  console.log("PROTOCOL_DISCOVERY_LOG_END");

  // Print instructions
  console.log("\n[ProtocolDiscovery] Complete!");
  console.log("  Log saved to: logs/sessions/protocol_*.log");
}

// =============================================================================
// MAIN DISCOVERY LOGIC
// =============================================================================

console.log(`[ProtocolDiscovery] Will discover for ${DISCOVERY_DURATION_MS / 1000}s...`);
console.log("[ProtocolDiscovery] Press Ctrl+C to stop early (summary will print on timeout)");

Il2Cpp.perform(() => {
  discoveryStartTime = Date.now();
  console.log("[ProtocolDiscovery] Il2Cpp runtime ready, starting discovery...\n");

  // Load Assembly-CSharp
  const csharp = loadAssembly("Assembly-CSharp");
  if (!csharp) {
    console.log("[ProtocolDiscovery] ERROR: Could not load Assembly-CSharp!");
    return;
  }

  console.log("[ProtocolDiscovery] === HOOKING GAMEPROTOCOL NAMESPACE ===\n");

  // Hook all classes in GameProtocol namespace
  let classCount = 0;
  csharp.classes.forEach((clazz) => {
    if (clazz.namespace === "GameProtocol") {
      const hooked = hookClass(clazz.name, clazz);
      if (hooked > 0) {
        classCount++;
        // Log progress every 50 classes
        if (classCount % 50 === 0) {
          console.log(`[ProtocolDiscovery] Hooked ${classCount} classes (${totalHookedMethods} methods)...`);
        }
      }
    }
  });

  console.log(`\n[ProtocolDiscovery] === HOOKING COMPLETE ===`);
  console.log(`[ProtocolDiscovery] Hooked ${hookedClasses.size} classes with ${totalHookedMethods} methods`);
  console.log(`[ProtocolDiscovery] Monitoring for ${DISCOVERY_DURATION_MS / 1000} seconds...\n`);
  console.log("=".repeat(80));
  console.log("   LIVE PROTOCOL ACTIVITY");
  console.log("=".repeat(80) + "\n");

  setTimeout(() => {
    console.log("\n[ProtocolDiscovery] Discovery period complete!");
    printAndDumpLogs();
  }, DISCOVERY_DURATION_MS);
});
