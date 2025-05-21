import { X3DH } from '../index.ts';

describe('x3dh', () => {
  let x3dh;
  
  beforeAll(() => {
    x3dh = new X3DH('x25519', 'sha512', 'MyProtocol');
  });

  it('should return correct curve, hash, and info', () => {
    expect(x3dh.getCurve()).toBe('x25519');
    expect(x3dh.getHash()).toBe('sha512');
    expect(x3dh.getInfo()).toBe('MyProtocol');
  });

  
});