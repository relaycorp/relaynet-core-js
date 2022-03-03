# relaynet-core-js

This library implements the core of [Awala](https://awala.network) and is meant to be used by anyone using the network from a Node.js application. [Read the docs online](https://docs.relaycorp.tech/relaynet-core-js/).

Please note that this documentation is mostly incomplete because the interface exposed by this library is changing rapidly as of this writing. Also note that the examples in this documentation won't work until a gateway (e.g., [the desktop one](https://github.com/relaycorp/relaynet-gateway-desktop)) has been implemented. We expect the library to reach a stable status and its documentation to be completed by the end of Q3 2020.

## Install

`@relaycorp/relaynet-core` requires Node.js v10 or newer, and the latest stable release can be installed as follows:

```
npm install --save @relaycorp/relaynet-core
```

## Specs supported

This library supports the following Awala specs:

- [RS-000 (Awala Core)](https://specs.awala.network/RS-000).
- [RS-001 (RAMF v1)](https://specs.awala.network/RS-001).
- [RS-002 (Awala PKI)](https://specs.awala.network/RS-002).
- [RS-003 (Awala Channel Session Protocol)](https://specs.awala.network/RS-003).
- [RS-018 (Awala Cryptographic Algorithms, Version 1)](https://specs.awala.network/RS-018). In addition to the required algorithms, the following are also supported:
  - Hashing functions: SHA-384 and SHA-512.
  - Ciphers: AES-192 and AES-256.
  - ECDH curves: P-384 and P-521.

## Updates

Releases are automatically published on GitHub and NPM, and the [changelog can be found on GitHub](https://github.com/relaycorp/relaynet-core-js/releases). This project uses [semantic versioning](https://semver.org/).
