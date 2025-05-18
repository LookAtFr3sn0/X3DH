import { X3DH } from "./lib/sodium.js";

const x3dh = new X3DH('x25519', 'sha256', 'MyProtocol');
x3dh.encrypt('Hello, World!', new Uint8Array(32));