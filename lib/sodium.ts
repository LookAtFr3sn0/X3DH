import pkg from 'sodium-plus';
const { SodiumPlus, CryptographyKey } = pkg;

let sodium;

export class X3DH {
  private curve: 'x25519' | 'x448';
  private hash: 'sha256' | 'sha512';
  private info: string;

  constructor(curve: 'x25519' | 'x448' = 'x25519', hash: 'sha256' | 'sha512' = 'sha512', info: string = 'MyProtocol') {
    this.curve  = curve;
    this.hash   = hash;
    this.info   = info;
  }

  private async initSodium() {
    if (!sodium) sodium = await SodiumPlus.auto();
    return sodium;
  }

  /**
   * Derives encryption key and commitment
   * @param {CryptographyKey} key
   * @param {Uint8Array} nonce
   * @returns {Promise<{ encryptionKey: CryptographyKey, commitment: Uint8Array }>}
   */
  public async deriveKeys(key: Uint8Array, nonce: Uint8Array): Promise<{ encryptionKey: Uint8Array, commitment: Uint8Array }> {
    const sodium = await this.initSodium();
    const cryptoKey = new CryptographyKey(Buffer.from(key));
    const encryptionKey = await sodium.crypto_generichash(
      Buffer.from(nonce),
      cryptoKey,
      32
    );
    const commitmentPrefix = Buffer.from(this.info + 'commitment', 'utf8');
    const commitment = await sodium.crypto_generichash(
      Buffer.concat([commitmentPrefix, nonce]),
      cryptoKey,
      32
    );
    return { encryptionKey, commitment };
  }

  /**
   * @param {string} message - The plaintext message to encrypt
   * @param {Uint8Array} key - The key to use for encryption
   * @param {string} [associatedData] - Optional associated data
   * @returns {string}
   */
  public async encrypt(message: string, key: Uint8Array, associatedData?: string): Promise<string> {
    const sodium = await this.initSodium();
    const nonceBuf = await sodium.randombytes_buf(24); // 192 bits nonce
    const nonce = Buffer.from(nonceBuf).toString('base64');
    const header = JSON.stringify({
      curve: this.curve,
      hash: this.hash,
      info: this.info,
      nonce: nonce,
      associatedData: associatedData || ''
    });
    const headerBuf = Buffer.from(header, 'utf8');
    const messageBuf = Buffer.from(message, 'utf8');
    const { encryptionKey, commitment } = await this.deriveKeys(key, nonceBuf);
    const ciphertext = await sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      messageBuf,
      nonceBuf,
      new CryptographyKey(Buffer.from(encryptionKey)),
      headerBuf
    );
    return JSON.stringify({
      header: header,
      commitment: Buffer.from(commitment).toString('base64'),
      ciphertext: Buffer.from(ciphertext).toString('base64')
    });
  }

  /**
   * @param {string} encrypted - JSON string containing the encrypted message and header with optional associated data
   * @param {Uint8Array} key - The key to use for decryption
   * @throws {Error} If the header does not match the expected values
   * @throws {Error} If decryption fails
   * @returns {Promise<string>}
   */
  public async decrypt(encrypted: string, key: Uint8Array): Promise<string> {
    const sodium = await this.initSodium();
    const parsed = JSON.parse(encrypted);
    const header = JSON.parse(parsed.header);
    if (header.curve !== this.curve || header.hash !== this.hash || header.info !== this.info) throw new Error('Header mismatch');
    const ciphertextBuf = Buffer.from(parsed.ciphertext, 'base64');
    const keyBuf = Buffer.from(key);
    const headerBuf = Buffer.from(parsed.header, 'utf8');
    const nonceBuf = Buffer.from(header.nonce, 'base64');
    const commitmentBuf = Buffer.from(parsed.commitment, 'base64');
    const { encryptionKey, commitment } = await this.deriveKeys(keyBuf, nonceBuf);
    if (!(await sodium.sodium_memcmp(commitmentBuf, commitment))) throw new Error('Commitment mismatch');
    const plaintext = await sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      ciphertextBuf,
      nonceBuf,
      new CryptographyKey(Buffer.from(encryptionKey)),
      headerBuf
    );
    if (!plaintext) throw new Error('Decryption failed');
    return plaintext.toString('utf8');
  }

  public getCurve(): 'x25519' | 'x448'   { return this.curve;  }
  public getHash():  'sha256' | 'sha512' { return this.hash;   }
  public getInfo():   string             { return this.info;   }
}