import pkg from 'sodium-plus';
const { SodiumPlus, CryptographyKey, X25519PublicKey, X25519SecretKey, Ed25519PublicKey, Ed25519SecretKey } = pkg;
import { createHmac } from 'crypto';

type Ed25519SecretKey = InstanceType<typeof Ed25519SecretKey>;

let sodium;

export class X3DH {
  private curve: 'x25519';
  private hash: 'sha256' | 'sha512';
  private info: string;

  constructor(curve: 'x25519' = 'x25519', hash: 'sha256' | 'sha512' = 'sha512', info: string = 'MyProtocol') {
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
 * @param {string} curve - The curve to use
 * @throws {Error} If the curve is not supported or not implemented
 * @returns {{ publicKey: X25519PublicKey, privateKey: X25519SecretKey }}
 */
  public async generateKeyPair(curve: 'x25519' = 'x25519') {
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

  /**
   * Hash public key
   * @param {Uint8Array[]} publicKeys - Array of public keys to hash
   * @throws {Error} If the hash function is not supported
   * @returns {Promise<Uint8Array>} - The hash of the public keys
   */
  public async hashPublicKeys(publicKeys: Uint8Array[]): Promise<Uint8Array> {
    const sodium = await this.initSodium();
    if (!Array.isArray(publicKeys)) publicKeys = [publicKeys];
    const hashState = await sodium.crypto_generichash_init();
    const length = new Uint8Array([
      (publicKeys.length >>> 24) & 0xFF,
      (publicKeys.length >>> 16) & 0xFF,
      (publicKeys.length >>> 8) & 0xFF,
      publicKeys.length & 0xFF
    ]);
    if (this.hash === 'sha256') {
      await sodium.crypto_hash_sha256_update(hashState, length);
      for (const publicKey of publicKeys) {
        await sodium.crypto_hash_sha256_update(hashState, Buffer.from(publicKey));
      }
      const finalHash = await sodium.crypto_hash_sha256_final(hashState, 32);
      return finalHash;
    } else if (this.hash === 'sha512') {
      await sodium.crypto_hash_sha512_update(hashState, length);
      for (const publicKey of publicKeys) {
        await sodium.crypto_hash_sha512_update(hashState, Buffer.from(publicKey));
      }
      const finalHash = await sodium.crypto_hash_sha512_final(hashState, 64);
      return finalHash;
    }
    throw new Error('Unsupported hash function');
  }

  /**
   * Sign a key ring with a private key.
   * @param {Ed22519SecretKey} privateKey - The private key to sign with
   * @param {Array<Uint8Array>} keyRing - The key ring to sign
   * @returns {Promise<Uint8Array>} - The signature of the key ring
   */
  public async signKeyRing(privateKey: Ed25519SecretKey, keyRing: Array<Uint8Array>): Promise<Uint8Array> {
    const sodium = await this.initSodium();
    const signature = await sodium.crypto_sign_detached(
      await this.hashPublicKeys(keyRing),
      privateKey
    );
    return signature;
  }

  /**
   * Generate n signed prekey
   * @param {Uint8Array} privateKey - The private key to sign with
   * @param {number} [count=50] - The number of signed prekeys to generate
   * @returns {Promise<{ signature: Uint8Array, preKeys: Uint8Array[] }>}
   */
  public async generatePreKeys(privateKey: Uint8Array, count: number = 50): Promise<{ signature: Uint8Array, preKeys: Uint8Array[] }> {
    const sodium = await this.initSodium();
    let keyRing = await this.generateKeyRing(count);
    const publicKeys = keyRing.map(key => key.publicKey);
    const edSecretKey = new Ed25519SecretKey(Buffer.from(privateKey));
    const signature = await this.signKeyRing(edSecretKey, publicKeys);

    let preKeys = [];
    for (let publicKey of publicKeys) {
      preKeys.push(Buffer.from(publicKey).toString('base64'));
    };

    return { signature, preKeys }
  }

  /**
   * Verify a signed key ring
   * @param {Uint8Array} publicKey - The public key to verify against
   * @param {Uint8Array} signature - The signature to verify
   * @param {Array<Uint8Array>} keyRing - The key ring to verify
   * @returns {Promise<boolean>}
   */
  public async verifyKeyRing(publicKey: Uint8Array, signature: Uint8Array, keyRing: Array<Uint8Array>): Promise<boolean> {
    const sodium = await this.initSodium();

    return sodium.crypto_sign_verify_detached(
      await this.hashPublicKeys(keyRing),
      Buffer.from(publicKey),
      Buffer.from(signature)
    )
  }

  /**
   * Begin a handshake with a remote party.
   * @param {Uint8Array} identityKey - The public key of the remote party
   * @param {Object} signedPreKey - The signed prekey from the local party
   * @param {Uint8Array} signedPreKey.signature - The signature of the signed prekey
   * @param {Uint8Array} signedPreKey.preKey - The prekey to use for the handshake
   * @param {Uint8Array} [oneTimeKey] - The recipient's one-time prekey
   * @param {Uint8Array} senderKey - The sender's private key
   * @throws {Error} If the signature verification fails
   * @returns {Promise<{ IK: Uint8Array, EK: Uint8Array, SK: Uint8Array, OTK?: Uint8Array }>}
   */
  public async handshakeBegin(
    identityKey: Uint8Array,
    signedPreKey: { signature: Uint8Array, preKey: Uint8Array },
    senderKey: Uint8Array,
    oneTimeKey?: Uint8Array
  ) {
    const sodium = await this.initSodium();
    const identity = new X25519PublicKey(Buffer.from(identityKey));
    const signature = Buffer.from(signedPreKey.signature);
    const prekey = new X25519PublicKey(Buffer.from(signedPreKey.preKey));

    if (!(await this.verifyKeyRing(identityKey, signature, [prekey.getBuffer()]))) {
      throw new Error('Signature verification failed for the signed prekey');
    }

    const ephemeralKeyPair = await this.generateKeyPair(this.curve);
    const ephemeralPublicKey = ephemeralKeyPair.publicKey;
    const ephemeralPrivateKey = ephemeralKeyPair.privateKey;

    const DH1 = await sodium.crypto_scalarmult(senderKey, prekey)
    const DH2 = await sodium.crypto_scalarmult(ephemeralPrivateKey, identity);
    const DH3 = await sodium.crypto_scalarmult(ephemeralPrivateKey, prekey);
    
    let SK = Buffer.concat([DH1, DH2, DH3]);
    if (oneTimeKey) {
      const DH4 = await sodium.crypto_scalarmult(
        ephemeralPrivateKey,
        new X25519PublicKey(Buffer.from(oneTimeKey))
      );

      SK = Buffer.concat([SK, DH4]);
      DH4.wipe();
    }
    SK = Buffer.from(await this.hkdf(SK));
    
    DH1.wipe();
    DH2.wipe();
    DH3.wipe();
    ephemeralPrivateKey.wipe();
    await sodium.sodium_memzero(senderKey.buffer);

    return {
      IK: identity.getBuffer(),
      EK: ephemeralPublicKey.getBuffer(),
      SK: SK,
      OTK: oneTimeKey ? Buffer.from(oneTimeKey) : null,
    }
    
  }

  public getCurve(): 'x25519'            { return this.curve; }
  public getHash():  'sha256' | 'sha512' { return this.hash;  }
  public getInfo():   string             { return this.info;  }
}