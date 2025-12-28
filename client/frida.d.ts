// Global Frida declarations
declare const Java: any;
declare const Module: {
  findExportByName(module: string | null, name: string): NativePointer | null;
  getExportByName(module: string | null, name: string): NativePointer;
  load(name: string): Module;
  findBaseAddress(name: string): NativePointer | null;
  getBaseAddress(name: string): NativePointer;
};

declare function send(message: any, data?: ArrayBuffer): void;
