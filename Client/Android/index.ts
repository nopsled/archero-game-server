import "frida-il2cpp-bridge";
import { FridaMultipleUnpinning } from "./multiple_unpinning";
import { Patcher } from "./socket_patcher";

// Start bypass SSL pinning
FridaMultipleUnpinning.bypass(false);
// Patch socket connect for port 443 to localhost
Patcher.PatchConnect("10.0.1.9", [443]);

Il2Cpp.perform(() => {
  console.log("[Agent]: Injected and rebuilded");

  const AssemblyCSharp = Il2Cpp.Domain.assembly("Assembly-CSharp").image;
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
  // const CustomBinaryWriter = AssemblyCSharp.class("CustomBinaryWriter");

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
  // UserResponse.methods.forEach((method => {
  //     UserResponse.method(method.name).implementation = function (this: any, ...args: any[]) {
  //         console.log("[UserResponse::" + method.name + "]: " + args.toString());
  //         return this.method(method.name).invoke(...args);
  //     }
  // }));
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
  // CUserLoginPacket.methods.forEach((method => {
  //     CUserLoginPacket.method(method.name).implementation = function (this: any, ...args: any[]) {
  //         log("[CUserLoginPacket::" + method.name + "]: " + args.toString());
  //         return this.method(method.name).invoke(...args);
  //     }
  // }));

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
