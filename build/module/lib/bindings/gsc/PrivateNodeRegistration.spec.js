import { Constructed, OctetString, Sequence } from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';
import { arrayBufferFrom, generateStubCert } from '../../_test_utils';
import { makeImplicitlyTaggedSequence } from '../../asn1';
import { derDeserialize } from '../../crypto_wrappers/_utils';
import { derSerializePublicKey } from '../../crypto_wrappers/keys';
import InvalidMessageError from '../../messages/InvalidMessageError';
import { SessionKeyPair } from '../../SessionKeyPair';
import { PrivateNodeRegistration } from './PrivateNodeRegistration';
let privateNodeCertificate;
let gatewayCertificate;
let sessionKey;
beforeAll(async () => {
    privateNodeCertificate = await generateStubCert();
    gatewayCertificate = await generateStubCert();
    sessionKey = (await SessionKeyPair.generate()).sessionKey;
});
describe('serialize', () => {
    test('Private node certificate should be serialized', async () => {
        const registration = new PrivateNodeRegistration(privateNodeCertificate, gatewayCertificate);
        const serialization = await registration.serialize();
        const sequence = derDeserialize(serialization);
        expect(sequence).toBeInstanceOf(Sequence);
        expect(sequence.valueBlock.value[0]).toHaveProperty('valueBlock.valueHex', privateNodeCertificate.serialize());
    });
    test('Gateway certificate should be serialized', async () => {
        const registration = new PrivateNodeRegistration(privateNodeCertificate, gatewayCertificate);
        const serialization = await registration.serialize();
        const sequence = derDeserialize(serialization);
        expect(sequence).toBeInstanceOf(Sequence);
        expect(sequence.valueBlock.value[1]).toHaveProperty('valueBlock.valueHex', gatewayCertificate.serialize());
    });
    describe('Session key', () => {
        test('Session key should be absent from serialization if it does not exist', async () => {
            const registration = new PrivateNodeRegistration(privateNodeCertificate, gatewayCertificate);
            const serialization = await registration.serialize();
            const sequence = derDeserialize(serialization);
            expect(sequence.valueBlock.value).toHaveLength(2);
        });
        test('Session key should be a CONSTRUCTED value', async () => {
            const registration = new PrivateNodeRegistration(privateNodeCertificate, gatewayCertificate, sessionKey);
            const serialization = await registration.serialize();
            const sequence = derDeserialize(serialization);
            const sessionKeySequence = sequence.valueBlock.value[2];
            expect(sessionKeySequence).toBeInstanceOf(Constructed);
        });
        test('Key id should be serialized', async () => {
            const registration = new PrivateNodeRegistration(privateNodeCertificate, gatewayCertificate, sessionKey);
            const serialization = await registration.serialize();
            const sequence = derDeserialize(serialization);
            expect(sequence.valueBlock.value[2].valueBlock.value[0]).toHaveProperty('valueBlock.valueHex', bufferToArray(sessionKey.keyId));
        });
        test('Public key should be serialized', async () => {
            const registration = new PrivateNodeRegistration(privateNodeCertificate, gatewayCertificate, sessionKey);
            const serialization = await registration.serialize();
            const sequence = await derDeserialize(serialization);
            expect(sequence.valueBlock.value[2].valueBlock.value[1]).toHaveProperty('valueBlock.valueHex', bufferToArray(await derSerializePublicKey(sessionKey.publicKey)));
        });
    });
});
describe('deserialize', () => {
    test('Serialization should be DER sequence', async () => {
        const invalidSerialization = arrayBufferFrom('nope.jpg');
        await expect(PrivateNodeRegistration.deserialize(invalidSerialization)).rejects.toThrowWithMessage(InvalidMessageError, 'Serialization is not a valid PrivateNodeRegistration');
    });
    test('Sequence should have at least two items', async () => {
        const invalidSerialization = makeImplicitlyTaggedSequence(new OctetString({ valueHex: arrayBufferFrom('nope.jpg') })).toBER();
        await expect(() => PrivateNodeRegistration.deserialize(invalidSerialization)).rejects.toThrowWithMessage(InvalidMessageError, 'Serialization is not a valid PrivateNodeRegistration');
    });
    test('Invalid private node certificates should be refused', async () => {
        const invalidSerialization = makeImplicitlyTaggedSequence(new OctetString({ valueHex: arrayBufferFrom('not a certificate') }), new OctetString({ valueHex: gatewayCertificate.serialize() })).toBER();
        await expect(() => PrivateNodeRegistration.deserialize(invalidSerialization)).rejects.toThrowWithMessage(InvalidMessageError, /^Private node certificate is invalid:/);
    });
    test('Invalid gateway certificates should be refused', async () => {
        const invalidSerialization = makeImplicitlyTaggedSequence(new OctetString({ valueHex: gatewayCertificate.serialize() }), new OctetString({ valueHex: arrayBufferFrom('not a certificate') })).toBER();
        await expect(() => PrivateNodeRegistration.deserialize(invalidSerialization)).rejects.toThrowWithMessage(InvalidMessageError, /^Gateway certificate is invalid:/);
    });
    describe('Session key', () => {
        test('SEQUENCE should contain at least two items', async () => {
            const invalidSerialization = makeImplicitlyTaggedSequence(new OctetString({ valueHex: gatewayCertificate.serialize() }), new OctetString({ valueHex: privateNodeCertificate.serialize() }), makeImplicitlyTaggedSequence(new OctetString({ valueHex: bufferToArray(sessionKey.keyId) }))).toBER();
            await expect(() => PrivateNodeRegistration.deserialize(invalidSerialization)).rejects.toThrowWithMessage(InvalidMessageError, 'Session key SEQUENCE should have at least 2 items');
        });
        test('Session key should be a valid ECDH public key', async () => {
            const invalidRegistration = new PrivateNodeRegistration(privateNodeCertificate, gatewayCertificate, {
                keyId: sessionKey.keyId,
                publicKey: await gatewayCertificate.getPublicKey(), // Invalid key type (RSA)
            });
            const invalidSerialization = await invalidRegistration.serialize();
            await expect(() => PrivateNodeRegistration.deserialize(invalidSerialization)).rejects.toThrowWithMessage(InvalidMessageError, /^Session key is not a valid ECDH public key:/);
        });
    });
    test('Valid registration with session key should be accepted', async () => {
        const registration = new PrivateNodeRegistration(privateNodeCertificate, gatewayCertificate, sessionKey);
        const serialization = await registration.serialize();
        const registrationDeserialized = await PrivateNodeRegistration.deserialize(serialization);
        expect(registrationDeserialized.privateNodeCertificate.isEqual(privateNodeCertificate)).toBeTrue();
        expect(registrationDeserialized.gatewayCertificate.isEqual(gatewayCertificate)).toBeTrue();
        expect(registrationDeserialized.sessionKey.keyId).toEqual(sessionKey.keyId);
        await expect(derSerializePublicKey(registrationDeserialized.sessionKey.publicKey)).resolves.toEqual(await derSerializePublicKey(sessionKey.publicKey));
    });
    test('Valid registration without session key should be accepted', async () => {
        const registration = new PrivateNodeRegistration(privateNodeCertificate, gatewayCertificate);
        const serialization = await registration.serialize();
        const registrationDeserialized = await PrivateNodeRegistration.deserialize(serialization);
        expect(registrationDeserialized.privateNodeCertificate.isEqual(privateNodeCertificate)).toBeTrue();
        expect(registrationDeserialized.gatewayCertificate.isEqual(gatewayCertificate)).toBeTrue();
    });
});
//# sourceMappingURL=PrivateNodeRegistration.spec.js.map