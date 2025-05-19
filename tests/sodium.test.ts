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

  it('should ')
});