import "frida-il2cpp-bridge";

declare const Java: any;
declare const Process: any;
declare const Memory: any;

function ts(): string {
    return new Date().toISOString();
}

console.log(`${ts()} [*] LibUnity Scanner started...`);

Java.perform(() => {
    // Wait for libunity.so to load
    const awaitLib = () => {
        const lib = Process.findModuleByName("libunity.so");
        if (!lib) {
            setTimeout(awaitLib, 500);
            return;
        }
        console.log(`${ts()} [+] libunity.so found at ${lib.base} (size: ${lib.size})`);
        scan(lib);
    };
    awaitLib();
});

function scan(lib: Module) {
    // 1. Search for the string "mbedtls_ssl_get_verify_result"
    // We search for just the function name mainly.
    const searchPattern = "mbedtls_ssl_get_verify_result"; 
    // Convert string to hex pattern or just use Memory.scan
    
    // We'll search explicitly for the bytes of the string
    // "mbedtls_ssl_get_verify_result"
    // 6d 62 65 64 74 6c 73 5f 73 73 6c 5f 67 65 74 5f 76 65 72 69 66 79 5f 72 65 73 75 6c 74
    
    const pattern = "6d 62 65 64 74 6c 73 5f 73 73 6c 5f 67 65 74 5f 76 65 72 69 66 79 5f 72 65 73 75 6c 74";
    
    Memory.scan(lib.base, lib.size, pattern, {
        onMatch(address, size) {
            console.log(`${ts()} [String] Found "${searchPattern}" at ${address} (offset: ${address.sub(lib.base)})`);
            findReferences(lib, address);
        },
        onError(reason) {
            console.log(`${ts()} [Scan Error] ${reason}`);
        },
        onComplete() {
            console.log(`${ts()} [Scan] String scan complete.`);
        }
    });

    // Also search for "X509 - Certificate verification failed, e.g. CRL, CA or signature check failed"
    // This is a common mbedtls error string: "Certificate verification failed"
    const pattern2 = "43 65 72 74 69 66 69 63 61 74 65 20 76 65 72 69 66 69 63 61 74 69 6f 6e 20 66 61 69 6c 65 64"; // "Certificate verification failed"
        Memory.scan(lib.base, lib.size, pattern2, {
        onMatch(address, size) {
            console.log(`${ts()} [String] Found "Certificate verification failed" at ${address} (offset: ${address.sub(lib.base)})`);
            findReferences(lib, address);
        },
        onComplete() { console.log("Scan 2 complete"); }
    });
}

function findReferences(lib: Module, targetAddr: NativePointer) {
    // Range to scan: Executable memory of the module
    const ranges = Process.enumerateRanges('r-x');
    for (const range of ranges) {
        if (range.base.compare(lib.base) >= 0 && 
            range.base.add(range.size).compare(lib.base.add(lib.size)) <= 0) {
            
            // Scan this range
            // Optimization: We only scan every 4 bytes (instruction alignment)
            // But doing this in JS loop is very slow.
            // We'll trust that the function we want is "mbedtls_x509_crt_verify"
            // and it might have a unique signature or string reference.
            
            // Instead of full scan, let's just define known mbedTLS signatures or
            // try to hook likely candidates by scanning for code patterns.
            
            // MbedTLS 2.x mbedtls_x509_crt_verify signature often starts with specific stack setup.
            // stp x29, x30, [sp, -#...]
            
            // Try to use Instruction.parse in a limited window if we found a string?
            // No, too slow.
        }
    }
    
    console.log(`[RefScan] Address ${targetAddr} found. Check offset ${targetAddr.sub(lib.base)} in IDA if possible.`);
}

// Improved plan:
// 1. We found the string "mbedtls_ssl_get_verify_result"
// 2. This string is likely used in `mbedtls_ssl_get_verify_result` function for debug logging?
//    Actually, looking at mbedtls source, `mbedtls_ssl_get_verify_result` just returns `ssl->session_negotiate->verify_result`.
//    It doesn't print anything.
//    The string "mbedtls_ssl_get_verify_result" might be function metadata or debug info.

// A better target string is "X509 - Certificate verification failed".
// This is used in `mbedtls_debug_print_msg`.

// Let's rely on finding standard mbedTLS exports by pattern matching code.
// mbedtls_x509_crt_verify usually calls `mbedtls_x509_crt_verify_restartable`.
// logic:
//   if ( (ret = mbedtls_x509_crt_verify_restartable( ... )) != 0 )
//   {
//       return( ret );
//   }

// We can scan for the machine code of `mbedtls_x509_crt_verify`.
// But that changes with compiler versions.

// Let's try to find symbols using `Module.enumerateExports` on libunity.so again.
// Sometimes they are there but hidden or oddly named.
