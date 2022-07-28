const SIGNATURE_PREFIX = Buffer.from('Awala');

export function generateFormatSignature(
  concreteMessageType: number,
  concreteMessageVersion: number,
): Uint8Array {
  const formatSignature = new Uint8Array(SIGNATURE_PREFIX.byteLength + 2);
  formatSignature.set(SIGNATURE_PREFIX, 0);
  formatSignature.set([concreteMessageType, concreteMessageVersion], SIGNATURE_PREFIX.byteLength);
  return formatSignature;
}
