import { X3DH } from "./lib/sodium.js";

const x3dh = new X3DH('x25519', 'sha256', 'MyProtocol');
const message = "Hello, world!";
const key = new Uint8Array(24);
console.log(key);
x3dh.hkdf(key).then(result => {
  console.log(result);
});