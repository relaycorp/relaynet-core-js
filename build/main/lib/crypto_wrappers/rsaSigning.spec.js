"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const _test_utils_1 = require("../_test_utils");
const utils = __importStar(require("./_utils"));
const keys_1 = require("./keys");
const rsaSigning_1 = require("./rsaSigning");
const plaintext = (0, _test_utils_1.arrayBufferFrom)('the plaintext');
const pkijsCrypto = utils.getPkijsCrypto();
// tslint:disable-next-line:no-let
let keyPair;
beforeAll(async () => {
    keyPair = await (0, keys_1.generateRSAKeyPair)();
});
describe('sign', () => {
    test('The plaintext should be signed with RSA-PSS, SHA-256 and a salt of 32', async () => {
        const signature = await (0, rsaSigning_1.sign)(plaintext, keyPair.privateKey);
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
        const anotherKeyPair = await (0, keys_1.generateRSAKeyPair)();
        const signature = await (0, rsaSigning_1.sign)(plaintext, anotherKeyPair.privateKey);
        await expect((0, rsaSigning_1.verify)(signature, keyPair.publicKey, plaintext)).resolves.toBeFalse();
    });
    test('Algorithms other than RSA-PSS with SHA-256 and MGF1 should be refused', async () => {
        const algorithmParams = {
            hash: { name: 'SHA-1' },
            name: 'RSA-PSS',
            saltLength: 20,
        };
        const invalidSignature = await pkijsCrypto.sign(algorithmParams, keyPair.privateKey, plaintext);
        await expect((0, rsaSigning_1.verify)(invalidSignature, keyPair.publicKey, plaintext)).resolves.toBeFalse();
    });
    test('Valid signatures should be accepted', async () => {
        const signature = await (0, rsaSigning_1.sign)(plaintext, keyPair.privateKey);
        await expect((0, rsaSigning_1.verify)(signature, keyPair.publicKey, plaintext)).resolves.toBeTrue();
    });
});
//# sourceMappingURL=rsaSigning.spec.js.map