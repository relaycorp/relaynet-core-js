import { arrayBufferFrom } from '../_test_utils';
import * as utils from './_utils';
import { generateRSAKeyPair } from './keys';
import { sign, verify } from './rsaSigning';
const plaintext = arrayBufferFrom('the plaintext');
const pkijsCrypto = utils.getPkijsCrypto();
// tslint:disable-next-line:no-let
let keyPair;
beforeAll(async () => {
    keyPair = await generateRSAKeyPair();
});
describe('sign', () => {
    test('The plaintext should be signed with RSA-PSS, SHA-256 and a salt of 32', async () => {
        const signature = await sign(plaintext, keyPair.privateKey);
        const rsaPssParams = {
            hash: { name: 'SHA-256' },
            name: 'RSA-PSS',
            saltLength: 32,
        };
        await pkijsCrypto.verify(rsaPssParams, keyPair.publicKey, signature, plaintext);
    });
});
describe('verify', () => {
    test('Invalid plaintexts should be refused', async () => {
        const anotherKeyPair = await generateRSAKeyPair();
        const signature = await sign(plaintext, anotherKeyPair.privateKey);
        await expect(verify(signature, keyPair.publicKey, plaintext)).resolves.toBeFalse();
    });
    test('Algorithms other than RSA-PSS with SHA-256 and MGF1 should be refused', async () => {
        const algorithmParams = {
            hash: { name: 'SHA-1' },
            name: 'RSA-PSS',
            saltLength: 20,
        };
        const invalidSignature = await pkijsCrypto.sign(algorithmParams, keyPair.privateKey, plaintext);
        await expect(verify(invalidSignature, keyPair.publicKey, plaintext)).resolves.toBeFalse();
    });
    test('Valid signatures should be accepted', async () => {
        const signature = await sign(plaintext, keyPair.privateKey);
        await expect(verify(signature, keyPair.publicKey, plaintext)).resolves.toBeTrue();
    });
});
//# sourceMappingURL=rsaSigning.spec.js.map