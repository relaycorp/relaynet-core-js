const SIGNATURE_PREFIX = Buffer.from('Relaynet');
export function generateFormatSignature(concreteMessageType, concreteMessageVersion) {
    const formatSignature = new Uint8Array(10);
    formatSignature.set(SIGNATURE_PREFIX, 0);
    formatSignature.set([concreteMessageType, concreteMessageVersion], 8);
    return formatSignature;
}
//# sourceMappingURL=formatSignature.js.map