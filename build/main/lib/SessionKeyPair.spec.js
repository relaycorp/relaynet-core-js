"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const keys_1 = require("./crypto_wrappers/keys");
const SessionKeyPair_1 = require("./SessionKeyPair");
describe('generate', () => {
    test('keyId should be randomly generated, 64-bit value', async () => {
        const { sessionKey } = await SessionKeyPair_1.SessionKeyPair.generate();
        expect(sessionKey.keyId).toBeInstanceOf(Buffer);
        expect(sessionKey.keyId.byteLength).toEqual(8);
    });
    test('publicKey should be output', async () => {
        const { sessionKey } = await SessionKeyPair_1.SessionKeyPair.generate();
        expect(sessionKey.publicKey.type).toEqual('public');
        expect(sessionKey.publicKey.algorithm.name).toEqual('ECDH');
    });
    test('privateKey should correspond to public key', async () => {
        const { sessionKey, privateKey } = await SessionKeyPair_1.SessionKeyPair.generate();
        expect(privateKey.type).toEqual('private');
        await expect((0, keys_1.derSerializePublicKey)(privateKey)).resolves.toEqual(await (0, keys_1.derSerializePublicKey)(sessionKey.publicKey));
    });
});
//# sourceMappingURL=SessionKeyPair.spec.js.map