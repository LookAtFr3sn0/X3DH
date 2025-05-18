export class X3DH {
  private curve: 'x25519' | 'x448';
  private hash: 'sha256' | 'sha512';
  private info: string;
  constructor (curve: 'x25519' | 'x448' = 'x25519', hash: 'sha256' | 'sha512' = 'sha512', info: string = 'MyProtocol') {
    this.curve = curve;
    this.hash = hash;
    this.info = info;
  }
}