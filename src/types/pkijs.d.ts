/* tslint:disable:readonly-array readonly-keyword */

declare module 'pkijs' {
  // Importing and exporting each member because "@types/pkijs" doesn't expose
  // the "pkijs" module -- it exports many individual modules. Also, the
  // following expression to export things in bulk didn't have any effect:
  //   export * from "pkijs/src/_x509";

  import AttributeTypeAndValue from 'pkijs/src/AttributeTypeAndValue';
  import AuthorityKeyIdentifier from 'pkijs/src/AuthorityKeyIdentifier';
  import Certificate from 'pkijs/src/Certificate';
  import ContentInfo from 'pkijs/src/ContentInfo';
  import CryptoEngine from 'pkijs/src/CryptoEngine';
  import Extension from 'pkijs/src/Extension';
  import IssuerAndSerialNumber from 'pkijs/src/IssuerAndSerialNumber';
  import PublicKeyInfo from 'pkijs/src/PublicKeyInfo';
  import RelativeDistinguishedNames from 'pkijs/src/RelativeDistinguishedNames';
  import SignedData from 'pkijs/src/SignedData';
  import SignerInfo from 'pkijs/src/SignerInfo';

  export {
    AttributeTypeAndValue,
    AuthorityKeyIdentifier,
    Certificate,
    ContentInfo,
    CryptoEngine,
    Extension,
    IssuerAndSerialNumber,
    PublicKeyInfo,
    RelativeDistinguishedNames,
    SignedData,
    SignerInfo
  };

  // Export all the stuff that "@types/pkijs" doesn't export but we use here

  export function setEngine(
    name: string,
    crypto: Crypto,
    subtle: SubtleCrypto
  ): void;
  export function getCrypto(): SubtleCrypto | undefined;

  export function getAlgorithmParameters(
    algorithmName: string,
    operation: string
  ): { algorithm: RsaHashedKeyGenParams; usages: string[] };
}
