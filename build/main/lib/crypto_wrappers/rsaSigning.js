"use strict";
/**
 * Plain RSA signatures are used when CMS SignedData can't be used. That is, when the signer
 * doesn't (yet) have a certificate.
 */
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
exports.verify = exports.sign = void 0;
const utils = __importStar(require("./_utils"));
const rsaPssParams = {
    hash: { name: 'SHA-256' },
    name: 'RSA-PSS',
    saltLength: 32,
};
const pkijsCrypto = utils.getPkijsCrypto();
async function sign(plaintext, privateKey) {
    return pkijsCrypto.sign(rsaPssParams, privateKey, plaintext);
}
exports.sign = sign;
async function verify(signature, publicKey, expectedPlaintext) {
    return pkijsCrypto.verify(rsaPssParams, publicKey, signature, expectedPlaintext);
}
exports.verify = verify;
//# sourceMappingURL=rsaSigning.js.map