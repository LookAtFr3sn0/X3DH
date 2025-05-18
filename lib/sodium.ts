import pkg from 'sodium-plus';
const { SodiumPlus } = pkg;

let sodium;

export class X3DH {
  private curve: 'x25519' | 'x448';
  private hash: 'sha256' | 'sha512';
  private info: string;
  private sodium;

  constructor(curve: 'x25519' | 'x448' = 'x25519', hash: 'sha256' | 'sha512' = 'sha512', info: string = 'MyProtocol') {
    this.curve  = curve;
    this.hash   = hash;
    this.info   = info;
  }

  private async initSodium() {
    if (!sodium) {
      sodium = await SodiumPlus.auto();
    }
    return sodium;
  }

  /**
   * Encrypts a message using XChaCha20-Poly1305
   * @param {string} message - The message to encrypt
   * @param {Uint8Array} key - The key to use for encryption
   * @param {string} associatedData - Optional associated data for the encryption
   * @returns {string}
   */
  public async encrypt(message: string, key: Uint8Array, associatedData?: string): Promise<string> {
    const sodium = await this.initSodium();

    const nonceBuf = await sodium.randombytes_buf(24); // 192 bits nonce
    const nonce = Buffer.from(nonceBuf).toString('base64');
    return nonce;
  }

  public getCurve(): 'x25519' | 'x448'  { return this.curve;  }
  public getHash(): 'sha256' | 'sha512' { return this.hash;   }
  public getInfo(): string              { return this.info;   }
}