import sodium from 'sodium-native';

export class X3DH {
  private curve: 'x25519' | 'x448';
  private hash: 'sha256' | 'sha512';
  private info: string;
  private sodium: typeof sodium;

  constructor (curve: 'x25519' | 'x448' = 'x25519', hash: 'sha512' | 'sha512' = 'sha512', info: string = 'MyProtocol') {
    this.curve = curve;
    this.hash = hash;
    this.info = info;
    this.sodium = sodium;
  }

  public getCurve(): 'x25519' | 'x448' {
    return this.curve;
  }
  public getHash(): 'sha256' | 'sha512' {
    return this.hash;
  }
  public getInfo(): string {
    return this.info;
  }
  public getSodium(): typeof sodium {
    return this.sodium;
  }


}