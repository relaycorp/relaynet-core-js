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
exports.generateRandom64BitValue = exports.derDeserialize = exports.getPkijsCrypto = void 0;
const asn1js = __importStar(require("asn1js"));
const pkijs = __importStar(require("pkijs"));
function getPkijsCrypto() {
    const cryptoEngine = pkijs.getCrypto();
    if (!cryptoEngine) {
        throw new Error('PKI.js crypto engine is undefined');
    }
    return cryptoEngine;
}
exports.getPkijsCrypto = getPkijsCrypto;
function derDeserialize(derValue) {
    const asn1Value = asn1js.fromBER(derValue);
    if (asn1Value.offset === -1) {
        throw new Error('Value is not DER-encoded');
    }
    return asn1Value.result;
}
exports.derDeserialize = derDeserialize;
function generateRandom64BitValue() {
    const value = new ArrayBuffer(8);
    // @ts-ignore
    getPkijsCrypto().getRandomValues(new Uint8Array(value));
    return value;
}
exports.generateRandom64BitValue = generateRandom64BitValue;
//# sourceMappingURL=_utils.js.map