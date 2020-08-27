//region Configure PKI.js
import { Crypto } from '@peculiar/webcrypto';
import { CryptoEngine, setEngine } from 'pkijs';

const crypto = new Crypto();
const cryptoEngine = new CryptoEngine({
  crypto,
  name: 'nodeEngine',
  subtle: crypto.subtle,
});
setEngine('nodeEngine', crypto, cryptoEngine);
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
export * from './lib/keyStores/privateKeyStore';
export * from './lib/keyStores/publicKeyStore';
export * from './lib/keyStores/testMocks';
export { default as PublicKeyStoreError } from './lib/keyStores/PublicKeyStoreError';
export { default as UnknownKeyError } from './lib/keyStores/UnknownKeyError';

export * from './lib/cargoRelay';

// PKI
export { default as Certificate } from './lib/crypto_wrappers/x509/Certificate';
export { default as CertificateError } from './lib/crypto_wrappers/x509/CertificateError';
export * from './lib/pki';

// CMS
export * from './lib/crypto_wrappers/cms/envelopedData';
export { SignatureOptions } from './lib/crypto_wrappers/cms/SignatureOptions';

// RAMF
export { default as Payload } from './lib/messages/payloads/PayloadPlaintext';
export { default as RAMFError } from './lib/ramf/RAMFError';
export { default as RAMFSyntaxError } from './lib/ramf/RAMFSyntaxError';
export { default as RAMFMessage } from './lib/messages/RAMFMessage';
export { default as Parcel } from './lib/messages/Parcel';
export { default as ServiceMessage } from './lib/messages/payloads/ServiceMessage';
export { default as Cargo } from './lib/messages/Cargo';
export { CargoCollectionAuthorization } from './lib/messages/CargoCollectionAuthorization';
export { default as CargoMessageSet } from './lib/messages/payloads/CargoMessageSet';
export { default as InvalidMessageError } from './lib/messages/InvalidMessageError';
export { default as RAMFValidationError } from './lib/ramf/RAMFValidationError';

// Control messages
export * from './lib/messages/ParcelCollectionAck';
export { ClientRegistrationAuthorization } from './lib/messages/bindings/pdc/ClientRegistrationAuthorization';
export { ClientRegistration } from './lib/messages/bindings/pdc/ClientRegistration';
// Nodes
export { Gateway, CargoMessageStream } from './lib/nodes/gateway';

//endregion
