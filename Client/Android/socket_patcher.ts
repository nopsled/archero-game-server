const getaddrinfoPtr = Module.findExportByName(null, "getaddrinfo");
const connectPtr = Module.findExportByName(null, "connect");
const sendPtr = Module.findExportByName(null, "send");
const recvPtr = Module.findExportByName(null, "recv");
const ntohsPtr = Module.findExportByName(null, "ntohs");
const inet_addrPtr = Module.findExportByName(null, "inet_addr");
if (
  getaddrinfoPtr != null &&
  connectPtr != null &&
  sendPtr != null &&
  recvPtr != null &&
  ntohsPtr != null &&
  inet_addrPtr != null
) {
  var getaddrinfoFunction = new NativeFunction(getaddrinfoPtr, "int", [
    "pointer",
    "pointer",
    "pointer",
    "pointer",
  ]);
  var connectFunction = new NativeFunction(connectPtr, "int", ["int", "pointer", "int"]);
  var sendFunction = new NativeFunction(sendPtr, "int", ["int", "pointer", "int", "int"]);
  var recvFunction = new NativeFunction(recvPtr, "int", ["int", "pointer", "int", "int"]);
  var ntohs = new NativeFunction(ntohsPtr, "uint16", ["uint16"]);
  var inet_addr = new NativeFunction(inet_addrPtr, "int", ["pointer"]);
  var connect = new NativeFunction(connectPtr, "int", ["int", "pointer", "uint"]);
}

class Utilities {
  /**
   * Returns hex from an ArrayBuffer object
   * @param {ArrayBuffer} array Array to work with
   * @param {Boolean} hex Whether to convert to hex or plain string
   */
  static getReadable(array: any, hex: any) {
    var result = new Uint8Array(array.byteLength);
    result.set(array, 0);
    if (hex == false) {
      var str = "";
      for (var i = 0; i < result.length; i++) {
        str += String.fromCharCode(result[i]);
      }
      return str;
    } else {
      var hexStr = "";
      for (var i = 0; i < result.length; i++) {
        hexStr += result[i].toString(16);
      }
      return hexStr;
    }
  }
  /**
   * Returns a nice formatting of a function with parameters
   * @param {string} functionName The name of the function to format
   * @param {string[]} params The function parameters as strings
   */
  static formatFunction(functionName: any, params: any, retval: any) {
    var result = "";
    result += functionName;
    result += "(";
    for (var i = 0; i < params.length; i++) {
      if (i != 0) {
        result += ", ";
      }
      result += params[i];
    }
    result += ")";
    if (retval) {
      result += " -> ";
      result += retval;
    }
    return result;
  }
}

export class Patcher {
  public static PatchGadp(addrInfo: string) {
    if (getaddrinfoPtr != null) {
      Interceptor.replace(
        getaddrinfoPtr,
        new NativeCallback(
          (name, service, req, pai) => {
            const nameStr = name.readUtf8String();
            const newNamePtr = Memory.allocUtf8String(addrInfo);
            console.log(Utilities.formatFunction("getaddrinfo", [nameStr, service, req, pai], ""));
            return getaddrinfoFunction(newNamePtr, service, req, pai);
          },
          "int",
          ["pointer", "pointer", "pointer", "pointer"]
        )
      );
    }
  }
  public static PatchConnect(newIP: string, ports = [443], isDebugging = false) {
    if (connectPtr != null) {
      Interceptor.replace(
        connectPtr,
        new NativeCallback(
          (socket, address, addressLen) => {
            var endpoint = {
              ip: "",
              port: 0,
            };
            var ip = [];
            const ipPtr = address.add(4);
            const portPtr = address.add(2);
            const port = ntohs(portPtr.readU16());
            endpoint.port = port;

            if (ports.includes(port)) {
              ipPtr.writeInt(inet_addr(Memory.allocUtf8String(newIP)));
              if (isDebugging) console.log("[Socket->connect()]: " + newIP + ":" + endpoint.port);
            }

            var result = connectFunction(socket, address, addressLen);
            return result;
          },
          "int",
          ["int", "pointer", "int"]
        )
      );
    }
  }
  public static PatchSend() {
    if (sendPtr != null) {
      Interceptor.replace(
        sendPtr,
        new NativeCallback(
          (fd, buf, len, flags) => {
            var buffer = buf.readByteArray(len);
            var result = sendFunction(fd, buf, len, flags);
            console.log(
              Utilities.formatFunction(
                "send",
                [fd, Utilities.getReadable(buffer, false), len, flags],
                result
              )
            );
            return result;
          },
          "int",
          ["int", "pointer", "int", "int"]
        )
      );
    }
  }
  public static PatchRecv() {
    if (recvPtr != null) {
      Interceptor.replace(
        recvPtr,
        new NativeCallback(
          (fd, buf, len, flags) => {
            var result = recvFunction(fd, buf, len, flags);
            if (result > -1) {
              var buffer = buf.readByteArray(result);
              console.log(
                Utilities.formatFunction(
                  "recv",
                  [fd, Utilities.getReadable(buffer, false), len, flags],
                  result
                )
              );
            } else {
              console.log(Utilities.formatFunction("recv", [fd, null, len, flags], result));
            }
            return result;
          },
          "int",
          ["int", "pointer", "int", "int"]
        )
      );
    }
  }
}

// const SocketFunctions = [
//     //'connect',
//     //'recv',
//     'send',
//     //'sendto',
//     //'read',
//     //'readfrom'
//     //'write'
// ]
// Process
//     .getModuleByName('libSystem.B.dylib')
//     .enumerateExports().filter(exp => exp.type === 'function' && SocketFunctions.some(prefix => exp.name.indexOf(prefix) === 0))
//     .forEach(exp => {
//         Interceptor.attach(exp.address, {
//             onEnter: function (args) {
//                 var fd = args[0].toInt32();
//                 var socktype = Socket.type(fd);
//                 //var data = args[1]
//                 //var size = args[2].toInt32();

//                 if (socktype !== 'tcp' && socktype !== 'tcp6')
//                     return;
//                 var address = Socket.peerAddress(fd);
//                 if (address === null)
//                     return;

//                 var data = args[1]
//                 var size = args[2].toInt32();
//                 var buffer = data.readByteArray(size);
//                 console.log(exp.name + "(" + fd + ")" + JSON.stringify(address) + " – " + size + " bytes (" + socktype + ")");
//                 if (buffer != null)
//                     console.log(hexdump(buffer, { offset: 0, length: 800, header: false, ansi: true }));

//             },
//             onLeave: function (retval) {
//             }
//         })
//     })

exports = Patcher;
exports = Utilities;
