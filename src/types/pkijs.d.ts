/* tslint:disable:readonly-array readonly-keyword */

declare module 'pkijs' {
  // Importing and exporting each member because "@types/pkijs" doesn't expose
  // the "pkijs" module -- it exports many individual modules. Also, the
  // following expression to export things in bulk didn't have any effect:
  //   export * from "pkijs/src/_x509";

  import Attribute from 'pkijs/src/Attribute';
  import AttributeTypeAndValue from 'pkijs/src/AttributeTypeAndValue';
  import AuthorityKeyIdentifier from 'pkijs/src/AuthorityKeyIdentifier';
  import BasicConstraints from 'pkijs/src/BasicConstraints';
  import Certificate from 'pkijs/src/Certificate';
  import ContentInfo from 'pkijs/src/ContentInfo';
  import CryptoEngine from 'pkijs/src/CryptoEngine';
  import EncapsulatedContentInfo from 'pkijs/src/EncapsulatedContentInfo';
  import EnvelopedData from 'pkijs/src/EnvelopedData';
  import Extension from 'pkijs/src/Extension';
  import IssuerAndSerialNumber from 'pkijs/src/IssuerAndSerialNumber';
  import KeyTransRecipientInfo from 'pkijs/src/KeyTransRecipientInfo';
  import PublicKeyInfo from 'pkijs/src/PublicKeyInfo';
  import RecipientInfo from 'pkijs/src/RecipientInfo';
  import RelativeDistinguishedNames from 'pkijs/src/RelativeDistinguishedNames';
  import RSAESOAEPParams from 'pkijs/src/RSAESOAEPParams';
  import SignedAndUnsignedAttributes from 'pkijs/src/SignedAndUnsignedAttributes';
  import SignedData from 'pkijs/src/SignedData';
  import SignerInfo from 'pkijs/src/SignerInfo';

  export {
    Attribute,
    AttributeTypeAndValue,
    AuthorityKeyIdentifier,
    BasicConstraints,
    Certificate,
    ContentInfo,
    CryptoEngine,
    EncapsulatedContentInfo,
    EnvelopedData,
    Extension,
    IssuerAndSerialNumber,
    KeyTransRecipientInfo,
    PublicKeyInfo,
    RecipientInfo,
    RelativeDistinguishedNames,
    RSAESOAEPParams,
    SignedAndUnsignedAttributes,
    SignedData,
    SignerInfo,
  };

  // Export all the stuff that "@types/pkijs" doesn't export but we use here

  export function setEngine(name: string, crypto: Crypto, subtle: SubtleCrypto): void;
  export function getCrypto(): SubtleCrypto | undefined;

  export function getAlgorithmParameters(
    algorithmName: string,
    operation: string,
  ): { algorithm: RsaHashedKeyGenParams; usages: string[] };
}
