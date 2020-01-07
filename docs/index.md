---
layout: page
title: Relaynet SDK
---
# Relaynet SDK

This library implements the core of Relaynet and is meant to be used by anyone using the network from a Node.js application.

## Install

`@relaycorp/relaynet-core` requires Node.js v10 or newer, and the latest stable release can be installed as follows:

```
npm install --save @relaycorp/relaynet-core
```

Development releases use the `dev` tag (`@relaycorp/relaynet-core@dev`).

## Use

This library can be used for different purposes, so please refer to the documentation for your specific use case:

Most people will be interested in [adding Relaynet support to their app](howto-service.md), whether the app is pre-existing or is being built from scratch.

Relaycorp provides implementations for gateways, relayers and bindings, so if you're contributing to those implementations or for whatever reason you'd like to build your own, please refer to the follow documents:

- [Implementing a binding](howto-binding.md).
- [Implementing a gateway](howto-gateway.md).
- [Implementing a relayer](howto-relayer.md).

TypeScript type declarations are included with this library. [Read API documentation](./api).

## Specs supported

This library supports the following Relaynet specs:

- [RS-000 (Relaynet Core)](https://specs.relaynet.link/RS-000).
- [RS-001 (RAMF v1)](https://specs.relaynet.link/RS-001).
- [RS-002 (Relaynet PKI)](https://specs.relaynet.link/RS-003).
- [RS-003 (Relaynet Channel Session Protocol)](https://specs.relaynet.link/RS-004).
- [RS-018 (Relaynet Cryptographic Algorithms, Version 1)](https://specs.relaynet.link/RS-004). In addition to the required algorithms, the following are also supported:
  - Hashing functions: SHA-384 and SHA-512.
  - Ciphers: AES-192 and AES-256.
  - ECDH curves: P-384 and P-521.

## Support

If you have any questions or comments, you can [find us on Gitter](https://gitter.im/relaynet/community) or [create an issue on the GitHub project](https://github.com/relaycorp/relaynet-core-js/issues/new/choose).

## Updates

Releases are automatically published on GitHub and NPM, and the [changelog can be found on GitHub](https://github.com/relaycorp/relaynet-core-js/releases). This project uses [semantic versioning](https://semver.org/).
