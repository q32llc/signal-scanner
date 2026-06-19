// Web globals a bare V8 isolate lacks, installed BEFORE linkedom/render load.
// (self/window are set by the host via context.eval before this bundle runs.)
import "fast-text-encoding";
import base64 from "base-64";
import { URL, URLSearchParams } from "whatwg-url-without-unicode";
const g = globalThis as any;
if (!g.atob) g.atob = (s: string) => base64.decode(String(s));
if (!g.btoa) g.btoa = (s: string) => base64.encode(String(s));
if (!g.URL) g.URL = URL;
if (!g.URLSearchParams) g.URLSearchParams = URLSearchParams;

// Minimal Buffer shim (linkedom's entity decoder + a few runtime paths use it).
// Built on the globals above; covers from(str|base64|bytes) + toString(enc).
if (!g.Buffer) {
  const toBinary = (bytes: Uint8Array): string => {
    let out = "";
    for (let i = 0; i < bytes.length; i += 8192) out += String.fromCharCode.apply(null, bytes.subarray(i, i + 8192) as unknown as number[]);
    return out;
  };
  g.Buffer = {
    from(input: unknown, enc?: string): Uint8Array & { toString: (e?: string) => string } {
      let bytes: Uint8Array;
      if (input instanceof Uint8Array) bytes = input;
      else if (enc === "base64") bytes = Uint8Array.from(g.atob(String(input)), (c: string) => c.charCodeAt(0));
      else bytes = new TextEncoder().encode(String(input));
      const view = bytes as Uint8Array & { toString: (e?: string) => string };
      view.toString = (e?: string) => (e === "binary" || e === "latin1" ? toBinary(bytes) : e === "base64" ? g.btoa(toBinary(bytes)) : new TextDecoder().decode(bytes));
      return view;
    },
    alloc: (n: number) => new Uint8Array(n),
    isBuffer: (x: unknown) => x instanceof Uint8Array
  };
}
