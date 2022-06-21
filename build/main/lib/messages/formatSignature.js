"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateFormatSignature = void 0;
const SIGNATURE_PREFIX = Buffer.from('Relaynet');
function generateFormatSignature(concreteMessageType, concreteMessageVersion) {
    const formatSignature = new Uint8Array(10);
    formatSignature.set(SIGNATURE_PREFIX, 0);
    formatSignature.set([concreteMessageType, concreteMessageVersion], 8);
    return formatSignature;
}
exports.generateFormatSignature = generateFormatSignature;
//# sourceMappingURL=formatSignature.js.map