//region Configure PKI.js
import WebCrypto from 'node-webcrypto-ossl';
import { CryptoEngine, setEngine } from 'pkijs';

const webcrypto = new WebCrypto();
const cryptoEngine = new CryptoEngine({
  crypto: webcrypto,
  name: 'nodeEngine',
  subtle: webcrypto.subtle,
});
setEngine('nodeEngine', webcrypto, cryptoEngine);
//endregion

//region Exports

export { default as RelaynetError } from './lib/RelaynetError';
export {
  derDeserializeECDHPrivateKey,
  derDeserializeECDHPublicKey,
  derDeserializeRSAPrivateKey,
  derDeserializeRSAPublicKey,
  derSerializePrivateKey,
  derSerializePublicKey,
  ECDHCurveName,
  generateECDHKeyPair,
  generateRSAKeyPair,
} from './lib/crypto_wrappers/keys';
export { PrivateKeyStore, PrivateKeyStoreError, PrivateKeyData } from './lib/privateKeyStore';

export * from './lib/cargoRelay';

// PKI
export { default as Certificate } from './lib/crypto_wrappers/x509/Certificate';
export { default as CertificateError } from './lib/crypto_wrappers/x509/CertificateError';
export * from './lib/pki';

// CMS
export * from './lib/crypto_wrappers/cms/envelopedData';
export { SignatureOptions } from './lib/crypto_wrappers/cms/signedData';

// RAMF
export { default as Message } from './lib/messages/Message';
export { default as Payload } from './lib/messages/PayloadPlaintext';
export { default as ServiceMessage } from './lib/messages/ServiceMessage';
export { default as RAMFError } from './lib/ramf/RAMFError';
export { default as RAMFSyntaxError } from './lib/ramf/RAMFSyntaxError';
export { default as RAMFValidationError } from './lib/ramf/RAMFValidationError';
export { default as InvalidMessageError } from './lib/messages/InvalidMessageError';
export { default as Parcel } from './lib/messages/Parcel';
export { default as Cargo } from './lib/messages/Cargo';

//endregion
