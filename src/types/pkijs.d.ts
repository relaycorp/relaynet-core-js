/* tslint:disable:readonly-array readonly-keyword */

declare module 'pkijs' {
  // Importing and exporting each member because "@types/pkijs" doesn't expose
  // the "pkijs" module -- it exports many individual modules. Also, the
  // following expression to export things in bulk didn't have any effect:
  //   export * from "pkijs/src/_x509";

  export { default as AlgorithmIdentifier } from 'pkijs/src/AlgorithmIdentifier';
  export { default as Attribute } from 'pkijs/src/Attribute';
  export { default as AttributeTypeAndValue } from 'pkijs/src/AttributeTypeAndValue';
  export { default as AuthorityKeyIdentifier } from 'pkijs/src/AuthorityKeyIdentifier';
  export { default as BasicConstraints } from 'pkijs/src/BasicConstraints';
  export { default as Certificate } from 'pkijs/src/Certificate';
  export { default as ContentInfo } from 'pkijs/src/ContentInfo';
  export { default as CryptoEngine } from 'pkijs/src/CryptoEngine';
  export { default as EncapsulatedContentInfo } from 'pkijs/src/EncapsulatedContentInfo';
  export { default as EnvelopedData } from 'pkijs/src/EnvelopedData';
  export { default as Extension } from 'pkijs/src/Extension';
  export { default as IssuerAndSerialNumber } from 'pkijs/src/IssuerAndSerialNumber';
  export { default as KeyAgreeRecipientInfo } from 'pkijs/src/KeyAgreeRecipientInfo';
  export { default as KeyTransRecipientInfo } from 'pkijs/src/KeyTransRecipientInfo';
  export { default as OtherRecipientInfo } from 'pkijs/src/OtherRecipientInfo';
  export { default as PublicKeyInfo } from 'pkijs/src/PublicKeyInfo';
  export { default as RecipientInfo } from 'pkijs/src/RecipientInfo';
  export { default as RelativeDistinguishedNames } from 'pkijs/src/RelativeDistinguishedNames';
  export { default as RSAESOAEPParams } from 'pkijs/src/RSAESOAEPParams';
  export { default as SignedAndUnsignedAttributes } from 'pkijs/src/SignedAndUnsignedAttributes';
  export { default as SignedData } from 'pkijs/src/SignedData';
  export { default as SignerInfo } from 'pkijs/src/SignerInfo';

  // Export all the stuff that "@types/pkijs" doesn't export but we use here

  export function setEngine(name: string, crypto: Crypto, subtle: SubtleCrypto): void;
  export function getCrypto(): SubtleCrypto | undefined;

  export function getAlgorithmParameters(
    algorithmName: string,
    operation: string,
  ): { algorithm: RsaHashedKeyGenParams; usages: string[] };
}
