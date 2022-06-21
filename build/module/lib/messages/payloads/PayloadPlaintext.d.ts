/**
 * Plaintext representation of a RAMF payload.
 *
 * Not to be confused with the final RAMF payload; e.g., a CMS EnvelopedData value containing the
 * ciphertext representation of the plaintext.
 */
export default interface PayloadPlaintext {
    readonly serialize: () => ArrayBuffer;
}
