import { X3DH } from "./lib/sodium.js";

const x3dh = new X3DH('x25519', 'sha256', 'MyProtocol');
const message = "Hello, world!";
const key = new Uint8Array(24);
x3dh.encrypt(message, key).then(result => {
  console.log("Encrypted message:", result);
  x3dh.decrypt(result, key).then(decrypted => {
    console.log("Decrypted message:", decrypted);
    console.log(message == decrypted);
  });
});