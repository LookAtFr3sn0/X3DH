# X3DH (Extended Triple Diffie-Hellman)

[![npm version](https://img.shields.io/npm/v/@lookatfr3sn0/x3dh)](https://www.npmjs.com/package/@lookatfr3sn0/x3dh)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A TypeScript implementation of the Extended Triple Diffie-Hellman (X3DH) key agreement protocol, also known as the Signal protocol. This library uses libsodium for cryptographic operations and is designed for secure end-to-end encryption (E2EE) and key exchange.

## Features
- X3DH key agreement protocol
- Uses libsodium for cryptography
- TypeScript support
- Suitable for E2EE and secure messaging

## Installation

```sh
npm install @lookatfr3sn0/x3dh
```

## Usage

```typescript
// ESM (recommended)
import { X3DH } from '@lookatfr3sn0/x3dh';

// CommonJS
const { X3DH } = require('@lookatfr3sn0/x3dh');
```

## Important Note on Hash Algorithm

Due to limitations of the underlying sodium-plus library, the `sha256` and `sha512` options for the hash algorithm actually use BLAKE2b under the hood. This means that while the API allows you to select `sha256` or `sha512`, the cryptographic operations are performed using BLAKE2b with output lengths matching those of SHA-256 (32 bytes) or SHA-512 (64 bytes).

## License

MIT © LookAtFr3sn0

## Links
- [GitHub Repository](https://github.com/LookAtFr3sn0/X3DH)
- [NPM Package](https://www.npmjs.com/package/@lookatfr3sn0/x3dh)