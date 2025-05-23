import { Ed25519PublicKey, Ed25519SecretKey, X25519PublicKey, X25519SecretKey } from 'sodium-plus';
import { X3DH } from '../index.ts';

describe('asymmetric', () => {
  let x3dh;

  beforeAll(() => {
    x3dh = new X3DH('x25519', 'sha512', 'MyProtocol');
  });

  it('should generate unique key pairs', async () => {
    const keyPair1 = await x3dh.asymmetric.generateKeyPair();
    const keyPair2 = await x3dh.asymmetric.generateKeyPair();
    const { publicKey: publicKey1, privateKey: privateKey1 } = keyPair1;
    const { publicKey: publicKey2, privateKey: privateKey2 } = keyPair2;
    const publicKey1Buffer = await publicKey1.getBuffer();
    const publicKey2Buffer = await publicKey2.getBuffer();
    const privateKey1Buffer = await privateKey1.getBuffer();
    const privateKey2Buffer = await privateKey2.getBuffer();
    expect(publicKey1Buffer).not.toEqual(publicKey2Buffer);
    expect(privateKey1Buffer).not.toEqual(privateKey2Buffer);
  });

  it('should generate a valid key pair', async () => {
    const keyPair = await x3dh.asymmetric.generateKeyPair();
    const { publicKey, privateKey } = keyPair;
    expect(publicKey).toBeInstanceOf(X25519PublicKey);
    expect(privateKey).toBeInstanceOf(X25519SecretKey);
    expect(publicKey).not.toEqual(privateKey);
  });

  it('should generate a key ring', async () => {
    const keyRing = await x3dh.asymmetric.generateKeyRing(5);
    expect(keyRing).toBeInstanceOf(Array<{ publicKey: Uint8Array, privateKey: Uint8Array }>);
    expect(keyRing.length).toBe(5);
    keyRing.forEach((keyPair) => {
      expect(keyPair.publicKey).toBeInstanceOf(X25519PublicKey);
      expect(keyPair.privateKey).toBeInstanceOf(X25519SecretKey);
      expect(keyPair.publicKey).not.toEqual(keyPair.privateKey);
    });
  });

  it('should hash a key ring', async () => {
    const keyRing = await x3dh.asymmetric.generateKeyRing(5);
    const publicKeys = keyRing.map(kp => kp.publicKey);
    const hash = await x3dh.asymmetric.hashPublicKeys(publicKeys);
    expect(hash).toBeInstanceOf(Uint8Array);
    expect(hash.length).toBe(64);
  });

  it('should generate an empty key ring if count is 0', async () => {
    const keyRing = await x3dh.asymmetric.generateKeyRing(0);
    expect(Array.isArray(keyRing)).toBe(true);
    expect(keyRing.length).toBe(0);
  });

  it('should hash key rings deterministically', async () => {
    const keyRing = await x3dh.asymmetric.generateKeyRing(5);
    const publicKeys = keyRing.map(kp => kp.publicKey);
    const hash1 = await x3dh.asymmetric.hashPublicKeys(publicKeys);
    const hash2 = await x3dh.asymmetric.hashPublicKeys(publicKeys);
    expect(hash1).toEqual(hash2);
  });

  it('should sign a key ring', async () => {
    const sodium = await import('sodium-plus').then(m => m.SodiumPlus.auto());
    const edKeyPair = await sodium.crypto_sign_keypair();
    const edPrivateKey = await sodium.crypto_sign_secretkey(edKeyPair);

    const keyRing = await x3dh.asymmetric.generateKeyRing(5);
    const publicKeys = keyRing.map(kp => kp.publicKey);
    const signature = await x3dh.asymmetric.signKeyRing(edPrivateKey, publicKeys);

    expect(signature).toBeInstanceOf(Uint8Array);
    expect(signature.length).toBe(64);
  });

  it('should verify a signed key ring', async () => {
    const sodium = await import('sodium-plus').then(m => m.SodiumPlus.auto());
    const edKeyPair = await sodium.crypto_sign_keypair();
    const edPublicKey = await sodium.crypto_sign_publickey(edKeyPair);
    const edPrivateKey = await sodium.crypto_sign_secretkey(edKeyPair);

    const keyRing = await x3dh.asymmetric.generateKeyRing(5);
    const publicKeys = keyRing.map(kp => kp.publicKey);
    const signature = await x3dh.asymmetric.signKeyRing(edPrivateKey, publicKeys);
    expect(await x3dh.asymmetric.verifyKeyRing(edPublicKey, signature, publicKeys)).toBe(true);
  });

  it('should fail to verify a signed key ring with an invalid public key', async () => {
    const sodium = await import('sodium-plus').then(m => m.SodiumPlus.auto());
    const edKeyPair = await sodium.crypto_sign_keypair();
    const edPublicKey = await sodium.crypto_sign_publickey(edKeyPair);
    const edPrivateKey = await sodium.crypto_sign_secretkey(edKeyPair);

    const keyRing = await x3dh.asymmetric.generateKeyRing(5);
    const publicKeys = keyRing.map(kp => kp.publicKey);
    const signature = await x3dh.asymmetric.signKeyRing(edPrivateKey, publicKeys);
    publicKeys[0] = new Uint8Array(32).fill(1);

    await expect(x3dh.asymmetric.verifyKeyRing(edPublicKey, signature, publicKeys)).rejects.toThrow('All publicKeys must be X25519PublicKey instances');
  });

  it('should fail to verify a signed key ring with the wrong public key', async () => {
    const sodium = await import('sodium-plus').then(m => m.SodiumPlus.auto());
    const edKeyPair = await sodium.crypto_sign_keypair();
    const edPrivateKey = await sodium.crypto_sign_secretkey(edKeyPair);
    const wrongKeyPair = await sodium.crypto_sign_keypair();
    const wrongPublicKey = await sodium.crypto_sign_publickey(wrongKeyPair);

    const keyRing = await x3dh.asymmetric.generateKeyRing(5);
    const publicKeys = keyRing.map(kp => kp.publicKey);
    const signature = await x3dh.asymmetric.signKeyRing(edPrivateKey, publicKeys);

    await expect(x3dh.asymmetric.verifyKeyRing(wrongPublicKey, signature, publicKeys)).resolves.toBe(false);
  });

  it('should generate n signed prekeys', async () => {
    const sodium = await import('sodium-plus').then(m => m.SodiumPlus.auto());
    const edKeyPair = await sodium.crypto_sign_keypair();
    const edPrivateKey = await sodium.crypto_sign_secretkey(edKeyPair);

    const { signature, preKeys } = await x3dh.asymmetric.generatePreKeys(edPrivateKey, 5);
    expect(signature).toBeInstanceOf(Uint8Array);
    expect(signature.length).toBe(64);
    expect(preKeys.length).toBe(5);
    preKeys.forEach((preKey) => { expect(preKey).toBeInstanceOf(X25519PublicKey) });
  });
});