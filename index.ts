import { X3DH } from "./lib/sodium.js";

const x3dh = new X3DH('x25519', 'sha256', 'MyProtocol');
const message = "Hello, world!";
const key = new Uint8Array(32); // Replace with your actual key
x3dh.encrypt(message, key).then(result => console.log(result));