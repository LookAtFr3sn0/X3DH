import pkg from 'sodium-plus';
const { SodiumPlus, CryptographyKey } = pkg;
import { createHmac } from 'crypto';

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

  /**
   * HMAC-based Extract-and-Expand Key Derivation Function (RFC 5869)
   * @param {Uint8Array} ikm - Input keying material
   * @param {Uint8Array} [salt] - Optional salt (defaults to zero)
   * @returns {Promise<Uint8Array>}
   */
  public async hkdf(ikm: Uint8Array, salt?: Uint8Array): Promise<Uint8Array> {
    const sodium = await this.initSodium();
    // Determine hash output length and default salt
    const hashLen = this.hash === 'sha512' ? 64 : 32;
    if (!salt) salt = Buffer.alloc(hashLen);
    
    const prk = createHmac(this.hash, salt).update(Buffer.from(ikm)).digest();

    const infoBuf = Buffer.from(this.info, 'utf8');
    const okm = createHmac(this.hash, prk)
      .update(Buffer.concat([Buffer.alloc(0), infoBuf, Buffer.from([1])]))
      .digest();
    return okm;
  }

/**
 * Generate an X25519 key pair.
 * todo - Add support for X448
 * @param {string} curve - The curve to use
 * @throws {Error} If the curve is not supported or not implemented
 * @returns {{ publicKey: Uint8Array, privateKey: Uint8Array }}
 */
  public async generateKeyPair(curve: 'x25519' | 'x448' = 'x25519') {
    const sodium = await this.initSodium();
    if (curve !== 'x25519') throw new Error('Only x25519 is supported for key generation at this time');
    const keyPair = await sodium.crypto_box_keypair();
    const publicKey = await sodium.crypto_box_publickey(keyPair);
    const privateKey = await sodium.crypto_box_secretkey(keyPair);
    return { publicKey, privateKey };
  }

  /**
   * Generate multiple key pairs.
   * @param {number} [count=50] - The number of key pairs to generate
   * @returns {Promise<Array<{ publicKey: Uint8Array, privateKey: Uint8Array }>>}
   */
  public async generateKeyRing(count: number = 50): Promise<Array<{ publicKey: Uint8Array, privateKey: Uint8Array }>> {
    let keyRing = [];
    for (let i = 0; i < count; i++) {
      const keyPair = await this.generateKeyPair(this.curve);
      keyRing.push(keyPair);
    }
    return keyRing;
  }
  
  public getCurve(): 'x25519' | 'x448'   { return this.curve;  }
  public getHash():  'sha256' | 'sha512' { return this.hash;   }
  public getInfo():   string             { return this.info;   }
}