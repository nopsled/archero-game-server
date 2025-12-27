import "frida-il2cpp-bridge";

function log(message: string): void {
  console.log(message);
}

Il2Cpp.perform(() => {
  console.log("[AGENT]: Injected and rebuilt");

  // function pauseThread() {
  //     // Get a reference to the current thread
  //     var thread = ObjC.classes.NSThread.currentThread();

  //     // Call the sleepForTimeInterval method to pause the thread for 0.1 seconds
  //     thread.sleepForTimeInterval_(0.01);
  // }

  const AssemblyCSharp = Il2Cpp.Domain.assembly("Assembly-CSharp").image;
  const AssemblyHabbyMail = Il2Cpp.Domain.assembly("HabbyMailLib").image;
  const AssemblyHabbyTool = Il2Cpp.Domain.assembly("HabbyToolLib").image;
  const AssemblyLib = Il2Cpp.Domain.assembly("lib").image;
  const AssemblyUnityWebRequestModule = Il2Cpp.Domain.assembly(
    "UnityEngine.UnityWebRequestModule"
  ).image;
  const AssemblyCoreModule = Il2Cpp.Domain.assembly("UnityEngine.CoreModule").image;
  //const AssemblyLibA = Il2Cpp.Domain.assembly("lib").image;

  const JsonObject = AssemblyHabbyTool.class("Habby.Tool.JsonObject");
  const RequestPathObjectBase = AssemblyHabbyTool.class(
    "Habby.Tool.Http.Tool.RequestPathObjectBase"
  );

  const NetConfig = AssemblyCSharp.class("Dxx.Net.NetConfig");
  const NetManager = AssemblyCSharp.class("Dxx.Net.NetManager");
  const NetResponse = AssemblyCSharp.class("Dxx.Net.NetResponse");
  const CCommonRespMsg = AssemblyCSharp.class("GameProtocol.CCommonRespMsg");
  const HTTPSendClient = AssemblyCSharp.class("HTTPSendClient");

  const Debug = AssemblyCoreModule.class("UnityEngine.Debug");

  const KCP = AssemblyLib.class("Habby.Net.KCPCommand.KCP");
  const UpdateManager = AssemblyLib.class("Habby.UpdateTool.UpdateManager");

  const CertificateHandler = AssemblyUnityWebRequestModule.class(
    "UnityEngine.Networking.CertificateHandler"
  );
  const UnityWebRequest = AssemblyUnityWebRequestModule.class(
    "UnityEngine.Networking.UnityWebRequest"
  );
  const DownloadHandler = AssemblyUnityWebRequestModule.class(
    "UnityEngine.Networking.DownloadHandler"
  );
  const UploadHandler = AssemblyUnityWebRequestModule.class("UnityEngine.Networking.UploadHandler");

  //const HttpManager = AssemblyHabbyTool.class("Habby.Tool.Http.HttpManager");
  const DownLoadManager = AssemblyHabbyTool.class("Habby.DownLoad.DownLoadManager");
  const DownLoader = AssemblyHabbyTool.class("Habby.DownLoad.DownLoader");

  // Classes with activity + interest
  // const NetEnc = AssemblyCSharp.class("Habby.Archero.Crypto.NetEnc");
  // const TGAnalytics = AssemblyCSharp.class("Habby.TGAnalytics");
  // const PlayerPrefsEncrypt = AssemblyCSharp.class("PlayerPrefsEncrypt");
  // const TcpNetManager = AssemblyCSharp.class("TcpNetManager");
  const NetEncrypt = AssemblyCSharp.class("NetEncrypt");
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
  const HabbyClient = AssemblyCSharp.class("HabbyClient");

  //const CustomBinaryWriter = AssemblyCSharp.class("CustomBinaryWriter");

  // Not interesting classes
  // const Http = AssemblyCSharp.class("Habby.Archero.Network.Http");

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

  // const HTTPSendClientIgnored = [
  //     "StartSend"
  // ]
  // HTTPSendClient.methods.forEach((method => {
  //     if (HTTPSendClientIgnored.includes(method.name)) return;
  //     HTTPSendClient.method(method.name).implementation = function (this: any, ...args: any[]) {
  //         log("[HTTPSendClient::" + method.name + "]: " + args.toString());
  //         return this.method(method.name).invoke(...args);
  //     }
  // }));

  // CCommonRespMsg.methods.forEach((method => {
  //     CCommonRespMsg.method(method.name).implementation = function (this: any, ...args: any[]) {
  //         log("[CCommonRespMsg::" + method.name + "]: " + args.toString());
  //         return this.method(method.name).invoke(...args);
  //     }
  // }));

  // NetConfig.methods.forEach((method => {
  //     NetConfig.method(method.name).implementation = function (this: any, ...args: any[]) {
  //         log("[NetConfig::" + method.name + "]: " + args.toString());
  //         return this.method(method.name).invoke(...args);
  //     }
  // }));

  // const NetManagerIgnored = [
  //     "get_IsLogin",
  //     "get_IsTest",
  //     "UpdateNetConnect",
  //     "get_IsNetConnect"
  // ]
  // NetManager.methods.forEach((method => {
  //     if (NetManagerIgnored.includes(method.name)) return;
  //     NetManager.method(method.name).implementation = function (this: any, ...args: any[]) {
  //         log("[NetManager::" + method.name + "]: " + args.toString());
  //         return this.method(method.name).invoke(...args);
  //     }
  // }));
  // NetResponse.methods.forEach((method => {
  //     NetResponse.method(method.name).implementation = function (this: any, ...args: any[]) {
  //         log("[NetResponse::" + method.name + "]: " + args.toString());
  //         return this.method(method.name).invoke(...args);
  //     }
  // }));

  CertificateHandler.methods.forEach((method) => {
    CertificateHandler.method(method.name).implementation = function (this: any, ...args: any[]) {
      log("[CertificateHandler::" + method.name + "]: " + args.toString());
      return this.method(method.name).invoke(...args);
    };
  });
  // DownloadHandler.methods.forEach((method => {
  //     DownloadHandler.method(method.name).implementation = function (this: any, ...args: any[]) {
  //         log("[DownloadHandler::" + method.name + "]: " + args.toString());
  //         return this.method(method.name).invoke(...args);
  //     }
  // }));
  // UploadHandler.methods.forEach((method => {
  //     UploadHandler.method(method.name).implementation = function (this: any, ...args: any[]) {
  //         log("[UploadHandler::" + method.name + "]: " + args.toString());
  //         return this.method(method.name).invoke(...args);
  //     }
  // }));
  // const UnityWebRequestIgnored = [
  //     "get_isDone"
  // ]
  // UnityWebRequest.methods.forEach((method => {
  //     if (UnityWebRequestIgnored.includes(method.name)) return;
  //     UnityWebRequest.method(method.name).implementation = function (this: any, ...args: any[]) {
  //         log("[UnityWebRequest::" + method.name + "]: " + args.toString());
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

  // HabbyClient.methods.forEach((method => {
  //     HabbyClient.method(method.name).implementation = function (this: any, ...args: any[]) {
  //         log("[HabbyClient::" + method.name + "]: " + args.toString());
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
  const NetEncryptIngoreMethods = ["Encrypt_Bytes"];
  NetEncrypt.methods.forEach((method) => {
    if (NetEncryptIngoreMethods.indexOf(method.name) > -1) return;
    NetEncrypt.method(method.name).implementation = function (this: any, ...args: any[]) {
      log("[NetEncrypt::" + method.name + "]: " + args.toString());
      console.log("");
      return this.method(method.name).invoke(...args);
    };
  });

  const SSLFunctions = [
    //"SSL_read",
    "SSL_write",
    //"SSL_do_handshake",
    //"SSL_is_dtls",
    //"SSL_get_session",
    //"SSL_in_init",
    // "SSL_SESSION_dup",
    // "SSL_SESSION_free",
    // "SSL_get_ex_data",
    // "SSL_SESSION_free",
    // "SSL_get1_session",
    // "SSL_in_init",
    // "SSL_get_certificate",
    // "SSL_get_peer_full_cert_chain",
    "SSL_CTX_set_cert_verify_callback",
    "SSL_CTX_set_info_callback",
  ];

  Process.getModuleByName("libboringssl.dylib")
    .enumerateExports()
    .filter(
      (exp) =>
        exp.type === "function" && SSLFunctions.some((prefix) => exp.name.indexOf(prefix) === 0)
    )
    .forEach((exp) => {
      Interceptor.attach(exp.address, {
        onEnter: function (args) {
          this.exp = exp;

          console.log(JSON.stringify(this.exp) + " - entered with args: " + JSON.stringify(args));

          if (exp.name === "SSL_write") {
            // Get the SSL context pointer from the first argument
            var sslContextPtr = args[0];
            // Read the data buffer from the second argument
            var dataPtr = args[1];
            var dataLength = args[2].toInt32();
            var data = dataPtr.readByteArray(dataLength);

            console.log(data);
          }

          if (exp.name === "SSL_read") {
            this.dataPtr = args[1];
          }
        },
        onLeave: function (retval: any) {
          //console.log(JSON.stringify(this.exp) + " -  returned: " + retval.toInt32());
          //console.log("");

          if (this.exp.name === "SSL_read") {
            var bufferContent = this.dataPtr.readByteArray(retval.toInt32());
            console.log("SSL_Reading: " + bufferContent.length + " bytes " + retval.toInt32());
            console.log(bufferContent);
            console.log("");
            console.log("");
          }
        },
      });
    });

  // const Security = Module.findExportByName(null, 'SSL_write');
  // if (Security != null) {
  //     console.log("SSLWrite found!-----------------------------------");
  //     Interceptor.attach(Security, {
  //         onEnter: function (args) {
  //             console.log("SSLWrite hooked................................")
  //             // Get the arguments passed to the SSLWrite function
  //             var sslContext = args[0];
  //             var data = args[1];
  //             var dataLength = args[2].toInt32();

  //             // Read the data buffer as a byte array
  //             if (dataLength > 0) {
  //                 let buffer = data.readByteArray(dataLength)
  //                 if (buffer != null) {
  //                     var byteArray = new Uint8Array(buffer);

  //                     // Convert the byte array to a string for logging
  //                     var dataString = byteArray.reduce(function (str, byte) {
  //                         return str + String.fromCharCode(byte);
  //                     }, '');

  //                     // Log the SSL data before encryption
  //                     console.log('SSL data (before encryption): ' + dataString);
  //                 }
  //             }

  //         }
  //     });
  // } else {
  //     console.log("SSLWrite not found")
  // }

  const SocketFunctions = [
    //'connect',
    //'recv',
    "send",
    //'sendto',
    //'read',
    //'readfrom'
    //'write'
  ];
  Process.getModuleByName("libSystem.B.dylib")
    .enumerateExports()
    .filter(
      (exp) =>
        exp.type === "function" && SocketFunctions.some((prefix) => exp.name.indexOf(prefix) === 0)
    )
    .forEach((exp) => {
      Interceptor.attach(exp.address, {
        onEnter: (args) => {
          var fd = args[0].toInt32();
          var socktype = Socket.type(fd);
          //var data = args[1]
          //var size = args[2].toInt32();

          if (socktype !== "tcp" && socktype !== "tcp6") return;
          var address = Socket.peerAddress(fd);
          if (address === null) return;

          var data = args[1];
          var size = args[2].toInt32();
          var buffer = data.readByteArray(size);
          console.log(
            exp.name +
              "(" +
              fd +
              ")" +
              JSON.stringify(address) +
              " – " +
              size +
              " bytes (" +
              socktype +
              ")"
          );
          if (buffer != null)
            console.log(hexdump(buffer, { offset: 0, length: 800, header: false, ansi: true }));
        },
        onLeave: (retval) => {},
      });
    });

  //  if (connect != null)
  //     Interceptor.attach(connect, {
  //         onEnter: function (args) {

  //             this.sockFd = args[0].toInt32()

  //             // var portLoc = args[1].add(2);
  //             // var ipLoc = args[1].add(4);
  //             // var port = ntohs(portLoc.readU16());

  //             // log("[Socket::Connect]: " + port);
  //             // // port === 9952 || 8080 || port === 443
  //             // if (port == 9952 || port == 8080 || port == 443) {

  //             //     var fd = args[0].toInt32();
  //             //     var socktype = Socket.type(fd);
  //             //     var host = inet_addr(Memory.allocUtf8String("10.0.1.9"))
  //             //     var ip = ntohs(ipLoc.readU16());

  //             //     ipLoc.writeInt(host);
  //             //     log("[Redirecting – Socket::Connect]: " + port);

  //             // }
  //         },
  //         onLeave: function (retval) {
  //             // const sockFd = this.sockFd
  //             // const sockType = Socket.type(sockFd)
  //             // const port = ntohs(portLoc.readU16());

  //             // if (!(sockType === "tcp6" || sockType === "tcp")) return

  //             // const sockLocal = Socket.localAddress(sockFd)
  //             // const sockRemote = Socket.peerAddress(sockFd)
  //             // if (sockRemote === null) return

  //             // log("[Socket::Connect (onLeave)]: " + port);

  //         }
  //     });
});
