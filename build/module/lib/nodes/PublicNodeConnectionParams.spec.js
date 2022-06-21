import { Constructed, OctetString, Sequence, VisibleString } from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';
import { arrayBufferFrom } from '../_test_utils';
import { makeImplicitlyTaggedSequence } from '../asn1';
import { derDeserialize } from '../crypto_wrappers/_utils';
import { derSerializePublicKey, generateECDHKeyPair, generateRSAKeyPair, } from '../crypto_wrappers/keys';
import { InvalidPublicNodeConnectionParams } from './errors';
import { PublicNodeConnectionParams } from './PublicNodeConnectionParams';
const PUBLIC_ADDRESS = 'example.com';
let identityKey;
let sessionKey;
beforeAll(async () => {
    const identityKeyPair = await generateRSAKeyPair();
    identityKey = identityKeyPair.publicKey;
    const sessionKeyPair = await generateECDHKeyPair();
    sessionKey = {
        keyId: Buffer.from('key id'),
        publicKey: sessionKeyPair.publicKey,
    };
});
describe('serialize', () => {
    test('Public address should be serialized', async () => {
        const params = new PublicNodeConnectionParams(PUBLIC_ADDRESS, identityKey, sessionKey);
        const serialization = await params.serialize();
        const sequence = derDeserialize(serialization);
        expect(sequence).toBeInstanceOf(Sequence);
        expect(sequence.valueBlock.value[0]).toHaveProperty('valueBlock.valueHex', arrayBufferFrom(PUBLIC_ADDRESS));
    });
    test('Identity key should be serialized', async () => {
        const params = new PublicNodeConnectionParams(PUBLIC_ADDRESS, identityKey, sessionKey);
        const serialization = await params.serialize();
        const sequence = derDeserialize(serialization);
        expect(sequence).toBeInstanceOf(Sequence);
        expect(sequence.valueBlock.value[1]).toHaveProperty('valueBlock.valueHex', bufferToArray(await derSerializePublicKey(identityKey)));
    });
    describe('Session key', () => {
        test('Session key should be a CONSTRUCTED value', async () => {
            const params = new PublicNodeConnectionParams(PUBLIC_ADDRESS, identityKey, sessionKey);
            const serialization = await params.serialize();
            const sequence = derDeserialize(serialization);
            const sessionKeySequence = sequence.valueBlock.value[2];
            expect(sessionKeySequence).toBeInstanceOf(Constructed);
        });
        test('Id should be serialized', async () => {
            const params = new PublicNodeConnectionParams(PUBLIC_ADDRESS, identityKey, sessionKey);
            const serialization = await params.serialize();
            const sequence = derDeserialize(serialization);
            expect(sequence.valueBlock.value[2].valueBlock.value[0]).toHaveProperty('valueBlock.valueHex', bufferToArray(sessionKey.keyId));
        });
        test('Public key should be serialized', async () => {
            const params = new PublicNodeConnectionParams(PUBLIC_ADDRESS, identityKey, sessionKey);
            const serialization = await params.serialize();
            const sequence = derDeserialize(serialization);
            expect(sequence.valueBlock.value[2].valueBlock.value[1]).toHaveProperty('valueBlock.valueHex', bufferToArray(await derSerializePublicKey(sessionKey.publicKey)));
        });
    });
});
describe('deserialize', () => {
    let identityKeySerialized;
    let sessionKeySerialized;
    beforeAll(async () => {
        identityKeySerialized = bufferToArray(await derSerializePublicKey(identityKey));
        sessionKeySerialized = bufferToArray(await derSerializePublicKey(sessionKey.publicKey));
    });
    let sessionKeySequence;
    beforeAll(() => {
        sessionKeySequence = makeImplicitlyTaggedSequence(new OctetString({ valueHex: bufferToArray(sessionKey.keyId) }), new OctetString({ valueHex: sessionKeySerialized }));
    });
    const malformedErrorMessage = 'Serialization is not a valid PublicNodeConnectionParams';
    test('Serialization should be DER sequence', async () => {
        const invalidSerialization = arrayBufferFrom('nope.jpg');
        await expect(PublicNodeConnectionParams.deserialize(invalidSerialization)).rejects.toThrowWithMessage(InvalidPublicNodeConnectionParams, malformedErrorMessage);
    });
    test('Sequence should have at least three items', async () => {
        const invalidSerialization = makeImplicitlyTaggedSequence(new OctetString({ valueHex: arrayBufferFrom('nope.jpg') }), new OctetString({ valueHex: arrayBufferFrom('whoops.jpg') })).toBER();
        await expect(PublicNodeConnectionParams.deserialize(invalidSerialization)).rejects.toThrowWithMessage(InvalidPublicNodeConnectionParams, malformedErrorMessage);
    });
    test('Public address should be syntactically valid', async () => {
        const invalidPublicAddress = 'not a public address';
        const invalidSerialization = makeImplicitlyTaggedSequence(new VisibleString({ value: invalidPublicAddress }), new OctetString({ valueHex: identityKeySerialized }), sessionKeySequence).toBER();
        await expect(PublicNodeConnectionParams.deserialize(invalidSerialization)).rejects.toThrow(new InvalidPublicNodeConnectionParams(`Public address is syntactically invalid (${invalidPublicAddress})`));
    });
    test('Identity key should be a valid RSA public key', async () => {
        const invalidSerialization = makeImplicitlyTaggedSequence(new VisibleString({ value: PUBLIC_ADDRESS }), new OctetString({
            valueHex: sessionKeySerialized, // Wrong type of key
        }), sessionKeySequence).toBER();
        await expect(PublicNodeConnectionParams.deserialize(invalidSerialization)).rejects.toThrowWithMessage(InvalidPublicNodeConnectionParams, /^Identity key is not a valid RSA public key/);
    });
    describe('Session key', () => {
        test('SEQUENCE should contain at least two items', async () => {
            const invalidSerialization = makeImplicitlyTaggedSequence(new VisibleString({ value: PUBLIC_ADDRESS }), new OctetString({ valueHex: identityKeySerialized }), makeImplicitlyTaggedSequence(new OctetString({ valueHex: bufferToArray(sessionKey.keyId) }))).toBER();
            await expect(PublicNodeConnectionParams.deserialize(invalidSerialization)).rejects.toThrowWithMessage(InvalidPublicNodeConnectionParams, 'Session key should have at least two items');
        });
        test('Session key should be a valid ECDH public key', async () => {
            const invalidSerialization = makeImplicitlyTaggedSequence(new VisibleString({ value: PUBLIC_ADDRESS }), new OctetString({ valueHex: identityKeySerialized }), makeImplicitlyTaggedSequence(new OctetString({ valueHex: bufferToArray(sessionKey.keyId) }), new OctetString({
                valueHex: identityKeySerialized, // Wrong type of key
            }))).toBER();
            await expect(PublicNodeConnectionParams.deserialize(invalidSerialization)).rejects.toThrowWithMessage(InvalidPublicNodeConnectionParams, /^Session key is not a valid ECDH public key/);
        });
    });
    test('Valid serialization should be deserialized', async () => {
        const params = new PublicNodeConnectionParams(PUBLIC_ADDRESS, identityKey, sessionKey);
        const serialization = await params.serialize();
        const paramsDeserialized = await PublicNodeConnectionParams.deserialize(serialization);
        expect(paramsDeserialized.publicAddress).toEqual(PUBLIC_ADDRESS);
        await expect(derSerializePublicKey(paramsDeserialized.identityKey)).resolves.toEqual(Buffer.from(identityKeySerialized));
        await expect(paramsDeserialized.sessionKey.keyId).toEqual(sessionKey.keyId);
        await expect(derSerializePublicKey(paramsDeserialized.sessionKey.publicKey)).resolves.toEqual(Buffer.from(sessionKeySerialized));
    });
});
//# sourceMappingURL=PublicNodeConnectionParams.spec.js.map