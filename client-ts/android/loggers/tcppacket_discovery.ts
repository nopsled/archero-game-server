/**
 * TCPPacket Discovery Tool
 *
 * Hooks all Il2Cpp classes in the "TCPPacket" namespace and logs every method call
 * during the first N seconds after the Unity runtime becomes available.
 *
 * Usage:
 *   cd client
 *   bun run build:tcppacket-discovery
 *   frida -D <device> -N com.habby.archero -l android/build/tcppacket_discovery.js
 */

import "frida-il2cpp-bridge";

console.log("[TCPPacketDiscovery] Script loaded");

const TARGET_NAMESPACE = "TCPPacket";
const DISCOVERY_DURATION_MS = 30000; // 30 seconds
const INCLUDE_CONSTRUCTORS = true;

interface MethodCall {
  t: number;
  c: string;
  m: string;
  a: string[];
  r?: string;
}

const methodCalls: MethodCall[] = [];
const hookedClasses: Map<string, number> = new Map();
let discoveryStartTime = 0;
let totalHookedMethods = 0;

function getElapsedSeconds(): number {
  return (Date.now() - discoveryStartTime) / 1000;
}

function formatTimestamp(): string {
  return getElapsedSeconds().toFixed(2);
}

function formatValue(value: any): string {
  if (value === null || value === undefined) return "<null>";

  try {
    if (value.class?.name === "String") {
      const content = value.content;
      return content ? `"${content}"` : "<empty string>";
    }

    if (value.class?.name === "Byte[]") {
      const len = value.length ?? 0;
      if (len === 0) return "<empty bytes>";
      const bytes: number[] = [];
      const maxShow = Math.min(len, 128);
      for (let i = 0; i < maxShow; i++) bytes.push(value.get_Item(i) & 0xff);
      return len > maxShow ? `[${bytes.join(",")} ...(+${len - maxShow})]` : `[${bytes.join(",")}]`;
    }

    const str = String(value);
    return str.length > 300 ? `${str.substring(0, 300)}...` : str;
  } catch {
    return "<unreadable>";
  }
}

function logMethodCall(className: string, methodName: string, args: any[], returnValue?: any) {
  const formattedArgs = args.map((a) => formatValue(a));
  const formattedReturn = returnValue !== undefined ? formatValue(returnValue) : undefined;

  methodCalls.push({
    t: Math.round(getElapsedSeconds() * 100) / 100,
    c: className,
    m: methodName,
    a: formattedArgs,
    r: formattedReturn,
  });

  const argsStr = formattedArgs.length > 0 ? `: ${formattedArgs.join(", ")}` : "";
  console.log(`[${formatTimestamp()}s][${className}::${methodName}]${argsStr}`);
  if (formattedReturn && formattedReturn !== "<null>") console.log(`  => ${formattedReturn}`);
}

const BASE_IGNORED_METHODS = [
  "Finalize",
  "ToString",
  "GetHashCode",
  "Equals",
  "Dispose",
];

function hookClass(fullName: string, clazz: Il2Cpp.Class): number {
  let hookedCount = 0;

  clazz.methods.forEach((method) => {
    const ignored = INCLUDE_CONSTRUCTORS
      ? BASE_IGNORED_METHODS
      : [...BASE_IGNORED_METHODS, ".ctor", ".cctor"];
    if (ignored.includes(method.name)) return;
    if (method.name.startsWith("get_") && method.parameterCount === 0) return;

    try {
      const paramSig = (() => {
        try {
          const names = method.parameters.map((p) => p.type.name);
          return `(${names.join(",")})`;
        } catch {
          return "";
        }
      })();
      const displayName = `${method.name}${paramSig}`;

      clazz.method(method.name).implementation = function (this: any, ...args: any[]) {
        const result = this.method(method.name).invoke(...args);
        logMethodCall(fullName, displayName, args, result);
        return result;
      };
      hookedCount++;
    } catch {
      // ignore
    }
  });

  if (hookedCount > 0) {
    hookedClasses.set(fullName, hookedCount);
    totalHookedMethods += hookedCount;
    if (hookedClasses.size % 25 === 0) {
      console.log(
        `[TCPPacketDiscovery] Progress: ${hookedClasses.size} classes (${totalHookedMethods} methods)`
      );
    }
  }

  return hookedCount;
}

function generateSummary(): object {
  const elapsed = getElapsedSeconds();

  const methodFreq: Map<string, number> = new Map();
  for (const call of methodCalls) {
    const key = `${call.c}::${call.m}`;
    methodFreq.set(key, (methodFreq.get(key) || 0) + 1);
  }

  const sortedMethods = [...methodFreq.entries()].sort((a, b) => b[1] - a[1]);
  const sortedClasses = [...hookedClasses.entries()].sort((a, b) => a[0].localeCompare(b[0]));

  return {
    session: {
      namespace: TARGET_NAMESPACE,
      durationSeconds: elapsed,
      timestamp: new Date().toISOString(),
      totalCalls: methodCalls.length,
      uniqueMethods: methodFreq.size,
      hookedClasses: Object.fromEntries(sortedClasses),
      totalHookedMethods,
    },
    methodFrequency: Object.fromEntries(sortedMethods),
    calls: methodCalls,
  };
}

console.log(
  `[TCPPacketDiscovery] Will hook namespace "${TARGET_NAMESPACE}" for ${DISCOVERY_DURATION_MS / 1000}s...`
);

Il2Cpp.perform(() => {
  discoveryStartTime = Date.now();
  console.log("[TCPPacketDiscovery] Il2Cpp runtime ready, scanning classes...");

  const candidates: Il2Cpp.Image[] = [];
  try {
    candidates.push(Il2Cpp.domain.assembly("Assembly-CSharp").image);
  } catch {
    // ignore
  }

  const seenImages = new Set<string>(candidates.map((i) => i.name));
  Il2Cpp.domain.assemblies.forEach((a) => {
    const img = a.image;
    if (img && !seenImages.has(img.name)) {
      seenImages.add(img.name);
      candidates.push(img);
    }
  });

  let foundClasses = 0;
  candidates.forEach((img) => {
    try {
      img.classes.forEach((clazz) => {
        if (clazz.namespace !== TARGET_NAMESPACE) return;
        foundClasses++;
        const fullName = `${clazz.namespace}.${clazz.name}`;
        hookClass(fullName, clazz);
      });
    } catch {
      // ignore images that fail enumeration
    }
  });

  if (foundClasses === 0) {
    console.log(`[TCPPacketDiscovery] No classes found in namespace "${TARGET_NAMESPACE}"`);
  } else {
    console.log(
      `[TCPPacketDiscovery] Hooked ${hookedClasses.size} classes (${totalHookedMethods} methods)`
    );
  }

  setTimeout(() => {
    console.log("\n[TCPPacketDiscovery] Discovery period complete!");
    console.log("TCPPACKET_DISCOVERY_LOG_START");
    console.log(JSON.stringify(generateSummary(), null, 2));
    console.log("TCPPACKET_DISCOVERY_LOG_END");
  }, DISCOVERY_DURATION_MS);
});
