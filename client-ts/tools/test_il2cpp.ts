import "frida-il2cpp-bridge";

function ts(): string {
    return new Date().toISOString();
}

console.log(`${ts()} [*] IL2CPP Test started...`);

Il2Cpp.perform(() => {
    try {
        console.log(`${ts()} [*] Attached to IL2CPP`);
        const domain = Il2Cpp.domain;
        console.log(`${ts()} [*] Domain: ${domain}`);
        const assemblies = domain.assemblies;
        console.log(`${ts()} [*] Assemblies count: ${assemblies.length}`);
        
        for (const asm of assemblies) {
            if (asm.name.includes("Unity") || asm.name.includes("System")) {
                console.log(`${ts()} [Assembly] ${asm.name} loaded`);
            }
        }
        console.log(`${ts()} [*] IL2CPP Test Passed`);
    } catch (e) {
        console.log(`${ts()} [!] IL2CPP Test Failed: ${e}`);
    }
});
