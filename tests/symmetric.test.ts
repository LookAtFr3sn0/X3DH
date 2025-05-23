import { X3DH } from '../index.ts';
import { CryptographyKey } from 'sodium-plus';

describe('symmetric', () => {
  let x3dh;

  beforeAll(() => {
    x3dh = new X3DH('x25519', 'sha512', 'MyProtocol');
  });

  it('should encrypt and decrypt a message', async () => {
    const symmetricKey = await CryptographyKey.from(crypto.getRandomValues(new Uint8Array(32)));
    const message = 'Hello world!';

    const encrypted = await x3dh.symmetric.encrypt(message, symmetricKey);
    expect(typeof encrypted).toBe('string');

    const decrypted = await x3dh.symmetric.decrypt(encrypted, symmetricKey);
    expect(decrypted).toBe(message);
  });

  it("shouldn't decrypt with wrong key", async () => {
    const symmetricKey = await CryptographyKey.from(crypto.getRandomValues(new Uint8Array(32)));
    const wrongKey = await CryptographyKey.from(crypto.getRandomValues(new Uint8Array(32)));
    const message = 'Hello world!';

    const encrypted = await x3dh.symmetric.encrypt(message, symmetricKey);
    await expect(x3dh.symmetric.decrypt(encrypted, wrongKey)).rejects.toThrow('Commitment mismatch');
  });

  it('should produce different ciphertexts for different keys', async () => {
    const key1 = await CryptographyKey.from(crypto.getRandomValues(new Uint8Array(32)));
    const key2 = await CryptographyKey.from(crypto.getRandomValues(new Uint8Array(32)));
    const message = 'Test message';

    const encrypted1 = await x3dh.symmetric.encrypt(message, key1);
    const encrypted2 = await x3dh.symmetric.encrypt(message, key2);
    expect(encrypted1).not.toBe(encrypted2);
  });

  it('should produce different ciphertexts for same key and message', async () => {
    const key = await CryptographyKey.from(crypto.getRandomValues(new Uint8Array(32)));
    const message = 'Repeatable message';

    const encrypted1 = await x3dh.symmetric.encrypt(message, key);
    const encrypted2 = await x3dh.symmetric.encrypt(message, key);
    expect(encrypted1).not.toBe(encrypted2);
  });

  it('should encrypt and decrypt an empty string', async () => {
    const key = await CryptographyKey.from(crypto.getRandomValues(new Uint8Array(32)));
    const message = '';
    const encrypted = await x3dh.symmetric.encrypt(message, key);
    const decrypted = await x3dh.symmetric.decrypt(encrypted, key);
    expect(decrypted).toBe(message);
  });
});
