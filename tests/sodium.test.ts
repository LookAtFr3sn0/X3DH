import { X3DH } from '../index.ts';

describe('X3DH', () => {
  let x3dh;

  beforeAll(() => {
    x3dh = new X3DH('x25519', 'sha512', 'MyProtocol');
  });

  it('should generate a valid key pair', async () => {
    const keyPair = await x3dh.generateKeyPair();
    const { publicKey, privateKey } = keyPair;
    expect(publicKey).toBeInstanceOf(Uint8Array);
    expect(privateKey).toBeInstanceOf(Uint8Array);
    expect(publicKey.length).toBe(32);
    expect(privateKey.length).toBe(32);
    expect(publicKey).not.toEqual(privateKey);
  });

  it('should encrypt and decrypt a message', async () => {
    const symmetricKey = crypto.getRandomValues(new Uint8Array(32));
    const message = 'Hello world!';

    const encrypted = await x3dh.encrypt(message, symmetricKey);
    expect(typeof encrypted).toBe('string');

    const decrypted = await x3dh.decrypt(encrypted, symmetricKey);
    expect(decrypted).toBe(message);
  });

  it('shouldn\'t decrypt with wrong key', async () => {
    const symmetricKey = crypto.getRandomValues(new Uint8Array(32));
    const wrongKey = crypto.getRandomValues(new Uint8Array(32));
    const message = 'Hello world!';

    const encrypted = await x3dh.encrypt(message, symmetricKey);
    await expect(x3dh.decrypt(encrypted, wrongKey)).rejects.toThrow('Commitment mismatch');
  });

  it('should produce different ciphertexts for different keys', async () => {
    const key1 = crypto.getRandomValues(new Uint8Array(32));
    const key2 = crypto.getRandomValues(new Uint8Array(32));
    const message = 'Test message';

    const encrypted1 = await x3dh.encrypt(message, key1);
    const encrypted2 = await x3dh.encrypt(message, key2);
    expect(encrypted1).not.toBe(encrypted2);
  });

  it('should produce different ciphertexts for same key and message', async () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const message = 'Repeatable message';

    const encrypted1 = await x3dh.encrypt(message, key);
    const encrypted2 = await x3dh.encrypt(message, key);
    expect(encrypted1).not.toBe(encrypted2);
  });

  it('should generate unique key pairs', async () => {
    const keyPair1 = await x3dh.generateKeyPair();
    const keyPair2 = await x3dh.generateKeyPair();
    expect(keyPair1.publicKey).not.toEqual(keyPair2.publicKey);
    expect(keyPair1.privateKey).not.toEqual(keyPair2.privateKey);
  });

  it('should encrypt and decrypt an empty string', async () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const message = '';
    const encrypted = await x3dh.encrypt(message, key);
    const decrypted = await x3dh.decrypt(encrypted, key);
    expect(decrypted).toBe(message);
  });

  
});