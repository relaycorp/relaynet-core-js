//region Configure PKI.js
import { CryptoEngine, setEngine } from 'pkijs';
import { AwalaCrypto } from './lib/crypto_wrappers/webcrypto/AwalaCrypto';

const crypto = new AwalaCrypto();
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
  getPublicKeyDigest,
  getPublicKeyDigestHex,
  getRSAPublicKeyFromPrivate,
  getPrivateAddressFromIdentityKey,
} from './lib/crypto_wrappers/keys';
export * from './lib/keyStores/privateKeyStore';
export * from './lib/keyStores/publicKeyStore';
export { KeyStoreSet } from './lib/keyStores/KeyStoreSet';
export { CertificateStore } from './lib/keyStores/CertificateStore';
export * from './lib/keyStores/testMocks';
export { default as PublicKeyStoreError } from './lib/keyStores/PublicKeyStoreError';
export { default as UnknownKeyError } from './lib/keyStores/UnknownKeyError';

export * from './lib/cargoRelay';

// PKI
export { default as Certificate } from './lib/crypto_wrappers/x509/Certificate';
export { default as CertificateError } from './lib/crypto_wrappers/x509/CertificateError';
export * from './lib/pki';

// CMS
export * from './lib/crypto_wrappers/cms/envelopedData'; // TODO: Remove
export { SessionKey } from './lib/SessionKey';
export { SessionKeyPair } from './lib/SessionKeyPair';
export { SignatureOptions } from './lib/crypto_wrappers/cms/SignatureOptions';
export { default as CMSError } from './lib/crypto_wrappers/cms/CMSError';

// RAMF
export { default as Payload } from './lib/messages/payloads/PayloadPlaintext';
export { default as RAMFError } from './lib/ramf/RAMFError';
export { default as RAMFSyntaxError } from './lib/ramf/RAMFSyntaxError';
export { MAX_RAMF_MESSAGE_LENGTH } from './lib/ramf/serialization';
export { default as RAMFMessage } from './lib/messages/RAMFMessage';
export { RecipientAddressType } from './lib/messages/RecipientAddressType';
export { default as Parcel } from './lib/messages/Parcel';
export { default as ServiceMessage } from './lib/messages/payloads/ServiceMessage';
export { default as Cargo } from './lib/messages/Cargo';
export { CargoCollectionAuthorization } from './lib/messages/CargoCollectionAuthorization';
export { CargoCollectionRequest } from './lib/messages/payloads/CargoCollectionRequest';
export { default as CargoMessageSet } from './lib/messages/payloads/CargoMessageSet';
export { default as InvalidMessageError } from './lib/messages/InvalidMessageError';
export { default as RAMFValidationError } from './lib/ramf/RAMFValidationError';

// Control messages
export * from './lib/messages/ParcelCollectionAck';
// GSC interface (for bindings like PoWeb)
export { GSCClient } from './lib/bindings/gsc/GSCClient';
export { StreamingMode } from './lib/bindings/gsc/StreamingMode';
export { HandshakeChallenge } from './lib/bindings/gsc/HandshakeChallenge';
export { HandshakeResponse } from './lib/bindings/gsc/HandshakeResponse';
export { ParcelCollection } from './lib/bindings/gsc/ParcelCollection';
export { ParcelDelivery } from './lib/bindings/gsc/ParcelDelivery';
export { PrivateNodeRegistrationAuthorization } from './lib/bindings/gsc/PrivateNodeRegistrationAuthorization';
export { PrivateNodeRegistration } from './lib/bindings/gsc/PrivateNodeRegistration';
export { PrivateNodeRegistrationRequest } from './lib/bindings/gsc/PrivateNodeRegistrationRequest';
export { CertificateRotation } from './lib/messages/CertificateRotation';
export * from './lib/messages/bindings/signatures';

// Nodes
export { Endpoint } from './lib/nodes/Endpoint';
export { EndpointManager } from './lib/nodes/managers/EndpointManager';
export { GatewayManager } from './lib/nodes/managers/GatewayManager';
export { Gateway } from './lib/nodes/Gateway';
export { CargoMessageStream } from './lib/nodes/CargoMessageStream';

//endregion

export { PublicNodeConnectionParams } from './lib/nodes/PublicNodeConnectionParams';
export * from './lib/nodes/errors';
export * from './lib/publicAddressing';
