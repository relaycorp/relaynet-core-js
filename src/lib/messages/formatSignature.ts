const SIGNATURE_PREFIX = Buffer.from('Relaynet');

export function generateFormatSignature(
  concreteMessageType: number,
  concreteMessageVersion: number,
): Uint8Array {
  const formatSignature = new Uint8Array(10);
  formatSignature.set(SIGNATURE_PREFIX, 0);
  formatSignature[8] = concreteMessageType;
  formatSignature[9] = concreteMessageVersion;
  return formatSignature;
}
