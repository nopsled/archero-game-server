import "frida-il2cpp-bridge";
import { FridaMultipleUnpinning } from "./patchers/multiple_unpinning";
import { NativeTlsBypass } from "./patchers/native_tls_bypass";
import { NativeTlsLogger } from "./loggers/native_tls_logger";
import { Patcher } from "./patchers/core/socket_patcher";

console.log("[Agent]: Script loaded");

// =============================================================================
// CONFIGURATION FLAGS
// =============================================================================

// Discovery mode: hook all Il2Cpp classes and log method calls for N seconds
const ENABLE_DISCOVERY_HOOKS = true;
const DISCOVERY_DURATION_MS = 30000; // 30 seconds

// Socket patching and traffic capture - disable for cleaner discovery output
const ENABLE_SOCKET_HOOKS = false;

// SSL pinning bypass and TLS logging - disable for cleaner discovery output
const ENABLE_SSL_BYPASS = false;
const ENABLE_NATIVE_TLS_BYPASS = false;
const ENABLE_NATIVE_TLS_LOGGER = false;

// Legacy Il2Cpp hooks (separate from discovery)
const ENABLE_IL2CPP_HOOKS = false;

// Traffic capture settings (only used when ENABLE_SOCKET_HOOKS = true)
const CAPTURE_ENABLED = true;
const TRAFFIC_CAPTURE_MODE = true;
const DISCOVERY_MODE = !TRAFFIC_CAPTURE_MODE;
const REDIRECT_GAME_TLS = false;
const LOCAL_TLS_PORT = 18443;
const TLS_LOG_MAX_BYTES = 4096;

// Game server IPs to capture traffic from (port 12020)
const GAME_SERVER_IPS = [
  "52.196.213.239", // Tokyo
  "52.58.11.88", // Frankfurt
  "52.76.226.28", // Singapore
];

const WATCH_HOSTNAMES = [
  "hotupdate-archero.habby.com",
  "game-archero-v1.archerosvc.com",
  "config-archero.archerosvc.com",
  "config.uca.cloud.unity3d.com",
  "cdp.cloud.unity3d.com",
  "mail-archero.habby.mobi",
] as const;

// =============================================================================
// SSL BYPASS (optional - disable for clean discovery output)
// =============================================================================
if (ENABLE_SSL_BYPASS) {
  FridaMultipleUnpinning.bypass(true);
  console.log("[Agent]: SSL pinning bypass enabled");
}

if (ENABLE_NATIVE_TLS_BYPASS) {
  try {
    NativeTlsBypass.enable(true);
    console.log("[Agent]: Native TLS bypass enabled");
  } catch (e) {
    console.log(`[Agent]: Native TLS bypass failed: ${String(e)}`);
  }
}

if (ENABLE_NATIVE_TLS_LOGGER) {
  try {
    const ok = NativeTlsLogger.enable([...WATCH_HOSTNAMES], TLS_LOG_MAX_BYTES);
    console.log(`[Agent]: Native TLS logger ${ok ? "enabled" : "not available"}`);
  } catch (e) {
    console.log(`[Agent]: Native TLS logger failed: ${String(e)}`);
  }
}

// =============================================================================
// SOCKET PATCHING (optional - disable for clean discovery output)
// =============================================================================
if (ENABLE_SOCKET_HOOKS) {
  if (REDIRECT_GAME_TLS) {
    Patcher.ConfigureTlsRemap({
      enabled: true,
      matchIp: "127.0.0.2",
      targetIp: "127.0.0.1",
      fromPort: 443,
      toPort: LOCAL_TLS_PORT,
      maxAgeMs: 2000,
    });
  }

  Patcher.PatchGetaddrinfoAllowlist(
    REDIRECT_GAME_TLS
      ? [
          "hotupdate-archero.habby.com",
          "game-archero-v1.archerosvc.com",
          "config-archero.archerosvc.com",
          "*.archerosvc.com",
          "mail-archero.habby.mobi",
        ]
      : [],
    "127.0.0.2",
    DISCOVERY_MODE,
    [...WATCH_HOSTNAMES]
  );

  Patcher.PatchConnect("127.0.0.1", [], false);

  Patcher.EnableCapture({
    enabled: CAPTURE_ENABLED,
    onlyTracked: false,
    onlyPatched: false,
    ports: [12020],
    maxBytes: 4096,
    emitMessages: false,
    emitConsole: true,
    captureReadWrite: true,
    captureSyscalls: false,
    decodeEnabled: true,
    decodePorts: [12020],
    decodeMaxChunkBytes: 65536,
    decodeMaxFrameBytes: 256 * 1024,
    decodeMaxFramesPerSocket: 50,
    decodeLogPayloadBytes: 256,
  });

  if (TRAFFIC_CAPTURE_MODE) {
    console.log("[Agent]: TRAFFIC CAPTURE MODE - capturing port 12020 data");
  }
}

// ============================================================================
// DISCOVERY HOOKS: Listen for all method and class calls for first 30 seconds
// ============================================================================
if (ENABLE_DISCOVERY_HOOKS) {
  console.log(
    `[Agent]: DISCOVERY MODE - will hook classes for ${DISCOVERY_DURATION_MS / 1000}s after Unity loads`
  );

  // Use setImmediate to avoid blocking spawn - Il2Cpp.perform is a spawn-gate
  setImmediate(() => {
    Il2Cpp.perform(() => {
      const discoveryStartTime = Date.now();
      let discoveryActive = true;

      // Helper function to check if discovery period is still active
      function isDiscoveryActive(): boolean {
        if (!discoveryActive) return false;
        if (Date.now() - discoveryStartTime > DISCOVERY_DURATION_MS) {
          if (discoveryActive) {
            discoveryActive = false;
            console.log("[Discovery]: 30 second discovery period ended");
          }
          return false;
        }
        return true;
      }

      // Helper function to convert byte array to hex string
      function bytesToHexDiscovery(bytes: any): string {
        if (!bytes) return "<null>";
        try {
          const len = bytes.Length || bytes.length || 0;
          if (len === 0) return "<empty>";
          const hexParts: string[] = [];
          for (let i = 0; i < Math.min(len, 256); i++) {
            const b = bytes.get_Item ? bytes.get_Item(i) : bytes[i];
            hexParts.push(("0" + (b & 0xff).toString(16)).slice(-2));
          }
          return hexParts.join(" ") + (len > 256 ? ` ...(+${len - 256}b)` : "");
        } catch (e) {
          return `<error: ${e}>`;
        }
      }

      // Helper to format arguments
      function formatArgs(args: any[]): string {
        return args
          .map((a: any) => {
            if (a === null || a === undefined) return "<null>";
            if (typeof a === "object" && (a.Length !== undefined || a.length !== undefined)) {
              return `[bytes: ${bytesToHexDiscovery(a)}]`;
            }
            try {
              const str = String(a);
              return str.length > 200 ? str.substring(0, 200) + "..." : str;
            } catch {
              return "<unreadable>";
            }
          })
          .join(", ");
      }

      // Generic hook installer for a class
      function hookClass(className: string, clazz: Il2Cpp.Class, ignoredMethods: string[] = []) {
        const defaultIgnored = ["Finalize", ".cctor", "ToString", "GetHashCode", "Equals"];
        const allIgnored = [...defaultIgnored, ...ignoredMethods];

        let hookedCount = 0;
        clazz.methods.forEach((method) => {
          if (allIgnored.includes(method.name)) return;
          // Skip property getters that are called frequently
          if (method.name.startsWith("get_") && method.parameterCount === 0) return;

          try {
            clazz.method(method.name).implementation = function (this: any, ...args: any[]) {
              if (isDiscoveryActive()) {
                const elapsed = ((Date.now() - discoveryStartTime) / 1000).toFixed(2);
                const argsStr = args.length > 0 ? formatArgs(args) : "";
                console.log(
                  `[${elapsed}s][${className}::${method.name}]${argsStr ? `: ${argsStr}` : ""}`
                );
              }
              const result = this.method(method.name).invoke(...args);
              if (isDiscoveryActive() && result !== null && result !== undefined) {
                if (
                  typeof result === "object" &&
                  (result.Length !== undefined || result.length !== undefined)
                ) {
                  console.log(`  => ${bytesToHexDiscovery(result)}`);
                }
              }
              return result;
            };
            hookedCount++;
          } catch (e) {
            // Silent fail for methods that can't be hooked
          }
        });
        console.log(`[Discovery]: Hooked ${hookedCount} methods on ${className}`);
      }

      // Try to load and hook classes from various assemblies
      const assemblies: Record<string, Il2Cpp.Image | null> = {};

      // Load assemblies safely
      function loadAssembly(name: string): Il2Cpp.Image | null {
        try {
          return Il2Cpp.domain.assembly(name).image;
        } catch (e) {
          console.log(`[Discovery]: Assembly "${name}" not found`);
          return null;
        }
      }

      assemblies.CSharp = loadAssembly("Assembly-CSharp");
      assemblies.UnityWebRequest = loadAssembly("UnityEngine.UnityWebRequestModule");
      assemblies.MsCorLib = loadAssembly("mscorlib");
      assemblies.HabbyMail = loadAssembly("HabbyMailLib");
      assemblies.HabbyTool = loadAssembly("HabbyToolLib");
      assemblies.Lib = loadAssembly("lib");
      assemblies.CoreModule = loadAssembly("UnityEngine.CoreModule");

      // Classes to hook - organized by category
      const classesToHook: Array<{ assembly: string; className: string; ignored?: string[] }> = [
        // Update/Download managers
        { assembly: "Lib", className: "Habby.UpdateTool.UpdateManager" },
        { assembly: "HabbyTool", className: "Habby.Tool.Http.HttpManager" },
        { assembly: "HabbyTool", className: "Habby.DownLoad.DownLoadManager" },
        { assembly: "HabbyTool", className: "Habby.DownLoad.DownLoader" },

        // Unity Web Request
        { assembly: "UnityWebRequest", className: "UnityEngine.Networking.CertificateHandler" },
        {
          assembly: "UnityWebRequest",
          className: "UnityEngine.Networking.UnityWebRequest",
          ignored: ["get_isDone", "get_timeout", "get_error", "Dispose", "Abort"],
        },
        {
          assembly: "UnityWebRequest",
          className: "UnityEngine.Networking.DownloadHandler",
          ignored: ["get_data", "Dispose"],
        },
        { assembly: "UnityWebRequest", className: "UnityEngine.Networking.UploadHandler" },

        // HTTP/Network
        {
          assembly: "CSharp",
          className: "HTTPSendClient",
          ignored: [
            "StartSend",
            "isTimeOut",
            "get_timeout",
            "get_starttime",
            "check_done",
            "get_IsCache",
          ],
        },

        // Crypto classes
        { assembly: "MsCorLib", className: "System.Security.Cryptography.SHA256" },
        { assembly: "MsCorLib", className: "System.Security.Cryptography.HashAlgorithm" },
        { assembly: "MsCorLib", className: "System.Security.Cryptography.RSA" },

        // Game-specific crypto/network classes
        { assembly: "CSharp", className: "Habby.Archero.Crypto.NetEnc" },
        { assembly: "CSharp", className: "Habby.TGAnalytics" },
        { assembly: "CSharp", className: "PlayerPrefsEncrypt" },
        { assembly: "CSharp", className: "TcpNetManager", ignored: ["Update"] },
        { assembly: "CSharp", className: "NetEncrypt" },
        { assembly: "CSharp", className: "RC4Encrypter" },
        { assembly: "CSharp", className: "SdkManager", ignored: ["_isDebugMode", "_isTestServer"] },
        { assembly: "CSharp", className: "GameProtocol.CUserLoginPacket" },

        // Habby.Mail system
        { assembly: "HabbyMail", className: "Habby.Mail.HabbyMailEventDispatch" },
        { assembly: "HabbyMail", className: "Habby.Mail.HabbyMailNoticeType" },
        { assembly: "HabbyMail", className: "Habby.Mail.MailHttpManager" },
        { assembly: "HabbyMail", className: "Habby.Mail.MailManager" },
        { assembly: "HabbyMail", className: "Habby.Mail.MailRequestPath" },
        { assembly: "HabbyMail", className: "Habby.Mail.MailSetting" },
        { assembly: "HabbyMail", className: "Habby.Mail.StoreChannel" },

        // Additional interesting classes
        { assembly: "CSharp", className: "S3SendClient" },
        { assembly: "CSharp", className: "S3SendMgr" },
        { assembly: "CSharp", className: "Debugger", ignored: ["get_bDebug"] },
        { assembly: "CSharp", className: "Habby.Net.Requests.RequestFactory" },
        { assembly: "CSharp", className: "Habby.Model.UserData" },
        { assembly: "CSharp", className: "HabbyClient" },
        { assembly: "CSharp", className: "Habby.Net.Responses.SyncUserResponse" },
        { assembly: "CSharp", className: "CustomBinaryWriter" },
        { assembly: "CSharp", className: "Dxx.Net.NetConfig" },
        {
          assembly: "CSharp",
          className: "Dxx.Net.NetManager",
          ignored: ["get_IsLogin", "get_IsTest", "UpdateNetConnect", "get_IsNetConnect"],
        },
        { assembly: "CSharp", className: "Dxx.Net.NetResponse" },
        { assembly: "CSharp", className: "GameProtocol.CCommonRespMsg" },
        { assembly: "HabbyTool", className: "Habby.Tool.JsonObject" },
        { assembly: "HabbyTool", className: "Habby.Tool.Http.Tool.RequestPathObjectBase" },
      ];

      // Hook all classes
      console.log("[Discovery]: Starting to hook classes...");
      for (const entry of classesToHook) {
        const assembly = assemblies[entry.assembly];
        if (!assembly) continue;

        try {
          const clazz = assembly.class(entry.className);
          hookClass(entry.className, clazz, entry.ignored || []);
        } catch (e) {
          console.log(`[Discovery]: Class "${entry.className}" not found in ${entry.assembly}`);
        }
      }

      console.log("[Discovery]: All hooks installed, monitoring for 30 seconds...");

      // Schedule cleanup message
      setTimeout(() => {
        console.log("[Discovery]: Discovery period complete. Hooks remain but logging stopped.");
      }, DISCOVERY_DURATION_MS);
    });
  });
}

if (!ENABLE_IL2CPP_HOOKS) {
  console.log("[Agent]: Il2Cpp hooks disabled (ENABLE_IL2CPP_HOOKS=false)");
} else {
  Il2Cpp.perform(() => {
    console.log("[Agent]: Injected and rebuilded");

    const AssemblyCSharp = Il2Cpp.domain.assembly("Assembly-CSharp").image;
    //const AssemblyUnityWebRequestModule = Il2Cpp.Domain.assembly("UnityEngine.UnityWebRequestModule").image;
    //const AssemblyMsCorLib = Il2Cpp.Domain.assembly("mscorlib").image;
    // const AssemblyHabbyMail = Il2Cpp.Domain.assembly("HabbyMailLib").image;
    // const AssemblyHabbyTool = Il2Cpp.Domain.assembly("HabbyToolLib").image;
    // const AssemblyLib = Il2Cpp.Domain.assembly("lib").image;
    // const AssemblyCoreModule = Il2Cpp.Domain.assembly("UnityEngine.CoreModule").image;
    // //const AssemblyLibA = Il2Cpp.Domain.assembly("lib").image;
    // const JsonObject = AssemblyHabbyTool.class("Habby.Tool.JsonObject");
    // const RequestPathObjectBase = AssemblyHabbyTool.class("Habby.Tool.Http.Tool.RequestPathObjectBase");
    // const NetConfig = AssemblyCSharp.class("Dxx.Net.NetConfig");
    // const NetManager = AssemblyCSharp.class("Dxx.Net.NetManager");
    // const NetResponse = AssemblyCSharp.class("Dxx.Net.NetResponse");
    // const CCommonRespMsg = AssemblyCSharp.class("GameProtocol.CCommonRespMsg");;

    const S3SendClient = AssemblyCSharp.class("S3SendClient");
    const S3SendMgr = AssemblyCSharp.class("S3SendMgr");
    const TGAnalytics = AssemblyCSharp.class("Habby.TGAnalytics");
    const Debugger = AssemblyCSharp.class("Debugger");
    const RequestFactory = AssemblyCSharp.class("Habby.Net.Requests.RequestFactory");
    const UserData = AssemblyCSharp.class("Habby.Model.UserData");
    const HabbyClient = AssemblyCSharp.class("HabbyClient");
    const UserResponse = AssemblyCSharp.class("Habby.Net.Responses.SyncUserResponse");
    const CUserLoginPacket = AssemblyCSharp.class("GameProtocol.CUserLoginPacket");

    // const UpdateManager = AssemblyLib.class("Habby.UpdateTool.UpdateManager");
    // const CertificateHandler = AssemblyUnityWebRequestModule.class("UnityEngine.Networking.CertificateHandler");
    // const UnityWebRequest = AssemblyUnityWebRequestModule.class("UnityEngine.Networking.UnityWebRequest");
    // const DownloadHandler = AssemblyUnityWebRequestModule.class("UnityEngine.Networking.DownloadHandler");
    // const UploadHandler = AssemblyUnityWebRequestModule.class("UnityEngine.Networking.UploadHandler");
    // const HTTPSendClient = AssemblyCSharp.class("HTTPSendClient")
    // //const Encoding = AssemblyMsCorLib.class("Encoding")
    // const SHA256 = AssemblyMsCorLib.class("System.Security.Cryptography.SHA256")
    // const HashAlgorithm = AssemblyMsCorLib.class("System.Security.Cryptography.HashAlgorithm")
    // const RSA = AssemblyMsCorLib.class("System.Security.Cryptography.RSA")
    // const HttpManager = AssemblyHabbyTool.class("Habby.Tool.Http.HttpManager");
    // const DownLoadManager = AssemblyHabbyTool.class("Habby.DownLoad.DownLoadManager");
    // const DownLoader = AssemblyHabbyTool.class("Habby.DownLoad.DownLoader");

    // Classes with activity + interest
    // const NetEnc = AssemblyCSharp.class("Habby.Archero.Crypto.NetEnc");
    // const TGAnalytics = AssemblyCSharp.class("Habby.TGAnalytics");
    // const PlayerPrefsEncrypt = AssemblyCSharp.class("PlayerPrefsEncrypt");
    // const TcpNetManager = AssemblyCSharp.class("TcpNetManager");
    // const NetEncrypt = AssemblyCSharp.class("NetEncrypt");
    // const RC4Encrypter = AssemblyCSharp.class("RC4Encrypter");
    // const SdkManager = AssemblyCSharp.class("SdkManager");
    // const CUserLoginPacket = AssemblyCSharp.class("GameProtocol.CUserLoginPacket");

    // Habby.Mail system (all dumped)
    // const HabbyMailEventDispatch = AssemblyHabbyMail.class("Habby.Mail.HabbyMailEventDispatch");
    // const HabbyMailNoticeType = AssemblyHabbyMail.class("Habby.Mail.HabbyMailNoticeType");
    // const MailHttpManager = AssemblyHabbyMail.class("Habby.Mail.MailHttpManager");
    // const MailManager = AssemblyHabbyMail.class("Habby.Mail.MailManager");
    // const MailRequestPath = AssemblyHabbyMail.class("Habby.Mail.MailRequestPath");
    // const MailSetting = AssemblyHabbyMail.class("Habby.Mail.MailSetting");
    // const StoreChannel = AssemblyHabbyMail.class("Habby.Mail.StoreChannel");
    const CustomBinaryWriter = AssemblyCSharp.class("CustomBinaryWriter");

    // Helper function to convert byte array to hex string
    function bytesToHex(bytes: any): string {
      if (!bytes) return "<null>";
      try {
        const len = bytes.Length || bytes.length || 0;
        if (len === 0) return "<empty>";
        const hexParts: string[] = [];
        for (let i = 0; i < Math.min(len, 512); i++) {
          const b = bytes.get_Item ? bytes.get_Item(i) : bytes[i];
          hexParts.push(("0" + (b & 0xff).toString(16)).slice(-2));
        }
        return hexParts.join(" ") + (len > 512 ? ` ...(+${len - 512}b)` : "");
      } catch (e) {
        return `<error: ${e}>`;
      }
    }

    // Hook CustomBinaryWriter to capture binary data being written
    const binaryWriterMethods = [
      "Write",
      "WriteBytes",
      "WriteByte",
      "WriteInt16",
      "WriteInt32",
      "WriteInt64",
      "WriteString",
      "WriteUInt16",
      "WriteUInt32",
      "WriteUInt64",
      "Flush",
      "Close",
      "ToArray",
      "GetBuffer",
    ];
    CustomBinaryWriter.methods.forEach((method) => {
      if (!binaryWriterMethods.some((m) => method.name.includes(m))) return;
      CustomBinaryWriter.method(method.name).implementation = function (this: any, ...args: any[]) {
        const result = this.method(method.name).invoke(...args);
        if (method.name === "ToArray" || method.name === "GetBuffer") {
          console.log(`[CustomBinaryWriter::${method.name}] => ${bytesToHex(result)}`);
        } else if (args.length > 0) {
          const argStr = args
            .map((a: any) => {
              if (a && a.length !== undefined && typeof a.length === "number" && a.length > 0) {
                return bytesToHex(a);
              }
              return String(a);
            })
            .join(", ");
          console.log(`[CustomBinaryWriter::${method.name}]: ${argStr}`);
        } else {
          console.log(`[CustomBinaryWriter::${method.name}]`);
        }
        return result;
      };
    });

    // Try to hook TcpNetManager for send/receive
    try {
      const TcpNetManager = AssemblyCSharp.class("TcpNetManager");
      TcpNetManager.methods.forEach((method) => {
        if (
          method.name.toLowerCase().includes("send") ||
          method.name.toLowerCase().includes("recv") ||
          method.name.toLowerCase().includes("receive")
        ) {
          TcpNetManager.method(method.name).implementation = function (this: any, ...args: any[]) {
            const argStr = args
              .map((a: any) => {
                if (a && typeof a === "object" && (a.Length || a.length)) {
                  return `[bytes: ${bytesToHex(a)}]`;
                }
                return String(a);
              })
              .join(", ");
            console.log(`[TcpNetManager::${method.name}]: ${argStr}`);
            const result = this.method(method.name).invoke(...args);
            if (result && typeof result === "object" && (result.Length || result.length)) {
              console.log(`[TcpNetManager::${method.name}] => ${bytesToHex(result)}`);
            }
            return result;
          };
        }
      });
      console.log("[Agent]: TcpNetManager hooks installed");
    } catch (e) {
      console.log(`[Agent]: TcpNetManager not found or hook failed: ${e}`);
    }

    // Try to hook NetEncrypt to see encrypted/decrypted bytes
    try {
      const NetEncrypt = AssemblyCSharp.class("NetEncrypt");
      NetEncrypt.methods.forEach((method) => {
        NetEncrypt.method(method.name).implementation = function (this: any, ...args: any[]) {
          const argStr = args
            .map((a: any) => {
              if (a && typeof a === "object" && (a.Length || a.length)) {
                return `[bytes: ${bytesToHex(a)}]`;
              }
              return String(a);
            })
            .join(", ");
          console.log(`[NetEncrypt::${method.name}]: ${argStr}`);
          const result = this.method(method.name).invoke(...args);
          if (result && typeof result === "object" && (result.Length || result.length)) {
            console.log(`[NetEncrypt::${method.name}] => ${bytesToHex(result)}`);
          }
          return result;
        };
      });
      console.log("[Agent]: NetEncrypt hooks installed");
    } catch (e) {
      console.log(`[Agent]: NetEncrypt not found: ${e}`);
    }

    S3SendMgr.methods.forEach((method) => {
      S3SendMgr.method(method.name).implementation = function (this: any, ...args: any[]) {
        console.log("[S3SendMgr::" + method.name + "]: " + args.toString());
        return this.method(method.name).invoke(...args);
      };
    });

    TGAnalytics.methods.forEach((method) => {
      //if (DebuggerIgnoredMethods.includes(method.name)) return;
      TGAnalytics.method(method.name).implementation = function (this: any, ...args: any[]) {
        console.log("[TGAnalytics::" + method.name + "]: " + args.toString());
        return this.method(method.name).invoke(...args);
      };
    });
    const DebuggerIgnoredMethods = ["get_bDebug"];
    // Debugger.methods.forEach((method => {
    //     if(DebuggerIgnoredMethods.includes(method.name)) return;
    //     Debugger.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         console.log("[Debugger::" + method.name + "]: " + args.toString());
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));
    UserResponse.methods.forEach((method) => {
      UserResponse.method(method.name).implementation = function (this: any, ...args: any[]) {
        console.log("[UserResponse::" + method.name + "]: " + args.toString());
        return this.method(method.name).invoke(...args);
      };
    });
    RequestFactory.methods.forEach((method) => {
      RequestFactory.method(method.name).implementation = function (this: any, ...args: any[]) {
        console.log("[RequestFactory::" + method.name + "]: " + args.toString());
        return this.method(method.name).invoke(...args);
      };
    });
    UserData.methods.forEach((method) => {
      UserData.method(method.name).implementation = function (this: any, ...args: any[]) {
        console.log("[UserData::" + method.name + "]: " + args.toString());
        return this.method(method.name).invoke(...args);
      };
    });
    HabbyClient.methods.forEach((method) => {
      HabbyClient.method(method.name).implementation = function (this: any, ...args: any[]) {
        console.log("[HabbyClient::" + method.name + "]: " + args.toString());
        return this.method(method.name).invoke(...args);
      };
    });

    // CertificateHandler.methods.forEach((method => {
    //     CertificateHandler.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         console.log("[CertificateHandler::" + method.name + "]: " + args.toString());
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));
    // const DownloadHandlerIgnored = [
    //     "get_data",
    //     "Dispose"
    // ]
    // DownloadHandler.methods.forEach((method => {
    //     if (DownloadHandlerIgnored.includes(method.name)) return;
    //     DownloadHandler.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         console.log("[DownloadHandler::" + method.name + "]: " + args.toString());
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));
    // UploadHandler.methods.forEach((method => {
    //     UploadHandler.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         console.log("[UploadHandler::" + method.name + "]: " + args.toString());
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));
    // const UnityWebRequestIgnored = [
    //     "get_isDone",
    //     "get_timeout",
    //     "Dispose",
    //     "Abort",
    //     "get_error"
    // ]
    // UnityWebRequest.methods.forEach((method => {
    //     if (UnityWebRequestIgnored.includes(method.name)) return;
    //     UnityWebRequest.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         console.log("[UnityWebRequest::" + method.name + "]: " + args.toString());
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));
    // const HTTPSendClientIgnored = [
    //     "StartSend",
    //     "isTimeOut",
    //     "get_timeout",
    //     "get_starttime",
    //     "check_done",
    //     "get_IsCache"
    // ]
    // HTTPSendClient.methods.forEach((method => {
    //     if (HTTPSendClientIgnored.includes(method.name)) return;

    //     HTTPSendClient.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         console.log("[HTTPSendClient::" + method.name + "]: " + args.toString());
    //     return this.method(method.name).invoke(...args);
    //     }
    // }));

    // SHA256.methods.forEach((method => {
    //     SHA256.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         console.log("[SHA256::" + method.name + "]: " + args.toString());
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));
    // HashAlgorithm.methods.forEach((method => {
    //     HashAlgorithm.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         console.log("[HashAlgorithm::" + method.name + "]: " + args.toString());
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));
    // RSA.methods.forEach((method =>  {
    //     RSA.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         console.log("[RSA::" + method.name + "]: " + args.toString());
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));

    // NetConfig.methods.forEach((method => {
    //     NetConfig.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         console.log("[NetConfig::" + method.name + "]: " + args.toString());
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));

    //     const NetManagerIgnored = [
    //     "get_IsLogin",
    //     "get_IsTest",
    //     "UpdateNetConnect",
    //     "get_IsNetConnect"
    // ]
    // NetManager.methods.forEach((method => {
    //     if (NetManagerIgnored.includes(method.name)) return;

    //     NetManager.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         console.log("[NetManager::" + method.name + "]: " + args.toString());
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));
    // NetResponse.methods.forEach((method => {
    //     NetResponse.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         console.log("[NetResponse::" + method.name + "]: " + args.toString());
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));

    // const DebugIgnored = [
    //     "StartSend"
    // ]
    // Debug.methods.forEach((method => {
    //     if (DebugIgnored.includes(method.name)) return;
    //     Debug.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         log("[Debug::" + method.name + "]: " + args.toString());
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));

    // CCommonRespMsg.methods.forEach((method => {
    //     CCommonRespMsg.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         log("[CCommonRespMsg::" + method.name + "]: " + args.toString());
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));

    // UpdateManager.methods.forEach((method => {
    //     UpdateManager.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         log("[UpdateManager::" + method.name + "]: " + args.toString());
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));

    // KCP.methods.forEach((method => {
    //     KCP.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         log("[KCP::" + method.name + "]: " + args.toString());
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));

    // RequestPathObjectBase.methods.forEach((method => {
    //     RequestPathObjectBase.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         log("[RequestPathObjectBase::" + method.name + "]: " + args.toString());
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));

    // JsonObject.methods.forEach((method => {
    //     JsonObject.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         log("[JsonObject::" + method.name + "]: " + args.toString());
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));
    // // HttpManager.methods.forEach((method => {
    // //     HttpManager.method(method.name).implementation = function (this: any, ...args: any[]) {
    // //         log("[HttpManager::" + method.name + "]: " + args.toString());
    // //         return this.method(method.name).invoke(...args);
    // //     }
    // // }));
    // DownLoadManager.methods.forEach((method => {
    //     DownLoadManager.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         log("[DownLoadManager::" + method.name + "]: " + args.toString());
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));
    // DownLoader.methods.forEach((method => {
    //     DownLoader.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         log("[DownLoader::" + method.name + "]: " + args.toString());
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));

    // HabbyMailEventDispatch.methods.forEach((method => {
    //     HabbyMailEventDispatch.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         log("[HabbyMailEventDispatch::" + method.name + "]: " + args.toString());
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));
    // HabbyMailNoticeType.methods.forEach((method => {
    //     HabbyMailNoticeType.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         log("[HabbyMailNoticeType::" + method.name + "]: " + args.toString());
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));
    // MailHttpManager.methods.forEach((method => {
    //     MailHttpManager.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         log("[MailHttpManager::" + method.name + "]: " + args.toString());
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));
    // MailManager.methods.forEach((method => {
    //     MailManager.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         log("[MailManager::" + method.name + "]: " + args.toString());
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));
    // MailRequestPath.methods.forEach((method => {
    //     MailRequestPath.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         log("[MailRequestPath::" + method.name + "]: " + args.toString());
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));
    // MailSetting.methods.forEach((method => {
    //     MailSetting.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         log("[MailSetting::" + method.name + "]: " + args.toString());
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));

    // Classes with activity and interest
    // TGAnalytics.methods.forEach((method => {
    //     TGAnalytics.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         log("[TGAnalytics::" + method.name + "]: " + args.toString());
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));
    // PlayerPrefsEncrypt.methods.forEach((method => {
    //     PlayerPrefsEncrypt.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         log("[PlayerPrefsEncrypt::" + method.name + "]: " + args.toString());
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));
    // const TcpNetManagerIgnoreMethods = [
    //     ""
    // ]
    // TcpNetManager.methods.forEach((method => {
    //     if (TcpNetManagerIgnoreMethods.indexOf(method.name) > -1) return;
    //     TcpNetManager.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         log("[TcpNetManager::" + method.name + "]: " + args.toString());
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));

    // const SdkManagerIgnoreMethods = [
    //     "_isDebugMode",
    //     "_isTestServer"
    // ]
    // SdkManager.methods.forEach((method => {
    //     if (SdkManagerIgnoreMethods.indexOf(method.name) > -1) return;
    //     SdkManager.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         log("[SdkManager::" + method.name + "]: " + args.toString());
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));
    CUserLoginPacket.methods.forEach((method) => {
      CUserLoginPacket.method(method.name).implementation = function (this: any, ...args: any[]) {
        console.log("[CUserLoginPacket::" + method.name + "]: " + args.toString());
        return this.method(method.name).invoke(...args);
      };
    });

    // ENCRYPTION ------------------------------------------------------------------
    // const RC4EncrypterIngoreMethods = [
    //     "get_pwd",
    //     "Encrypt"
    // ]
    // RC4Encrypter.methods.forEach((method => {
    //     if (RC4EncrypterIngoreMethods.indexOf(method.name) > -1) return;
    //     RC4Encrypter.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         log("[RC4Encrypter::" + method.name + "]: " + args.toString());
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));
    // Crypto.methods.forEach((method => {
    //     Crypto.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         log("[Crypto::" + method.name + "]: " + args.toString());
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));
    // NetEnc.methods.forEach((method => {
    //     NetEnc.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         log("[NetEnc::" + method.name + "]: " + args.toString());
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));
    // const NetEncryptIngoreMethods = [
    //     "Encrypt_Bytes"
    // ]
    // NetEncrypt.methods.forEach((method => {
    //     if (NetEncryptIngoreMethods.indexOf(method.name) > -1) return;
    //     NetEncrypt.method(method.name).implementation = function (this: any, ...args: any[]) {
    //         log("[NetEncrypt::" + method.name + "]: " + args.toString());
    //         console.log("")
    //         return this.method(method.name).invoke(...args);
    //     }
    // }));
  });
}
