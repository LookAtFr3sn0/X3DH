import { X3DH } from '../index.ts';

describe('X3DH', () => {
  let x3dh: X3DH;

  beforeAll(() => {
    x3dh = new X3DH('x25519', 'sha512', 'MyProtocol');
  });

  it('should generate a key pair', async () => {
    const keyPair = await x3dh.generateKeyPair();
    const { publicKey, privateKey } = keyPair;
    expect(publicKey).toBeInstanceOf(Uint8Array);
    expect(privateKey).toBeInstanceOf(Uint8Array);
    expect(publicKey.length).toBe(32);
    expect(privateKey.length).toBe(32);
  });
});