//region Configure PKI.js
import { CryptoEngine, setEngine } from 'pkijs';
import { AwalaCrypto } from './lib/crypto/webcrypto/AwalaCrypto';

const crypto = new AwalaCrypto();
const cryptoEngine = new CryptoEngine({
  crypto,
  name: 'nodeEngine',
  subtle: crypto.subtle,
});
setEngine('nodeEngine', cryptoEngine);
//endregion

//region Exports

export { RelaynetError } from './lib/RelaynetError';
export {
  generateECDHKeyPair,
  generateRSAKeyPair,
  getPublicKeyDigest,
  getPublicKeyDigestHex,
  getRSAPublicKeyFromPrivate,
  getIdFromIdentityKey,
  RSAKeyGenOptions,
} from './lib/crypto/keys/generation';
export { PrivateKey, RsaPssPrivateKey } from './lib/crypto/keys/PrivateKey';
export { ECDHCurveName } from './lib/crypto/algorithms';
export { IdentityKeyPair } from './lib/IdentityKeyPair';

export * from './lib/cargoRelay';

// PKI
export { Certificate } from './lib/crypto/x509/Certificate';
export { CertificationPath } from './lib/pki/CertificationPath';
export { CertificateError } from './lib/crypto/x509/CertificateError';
export * from './lib/pki/issuance';

// Key stores
export { PrivateKeyStore, SessionPrivateKeyData } from './lib/keyStores/PrivateKeyStore';
export * from './lib/keyStores/PublicKeyStore';
export { KeyStoreSet } from './lib/keyStores/KeyStoreSet';
export { CertificateStore } from './lib/keyStores/CertificateStore';
export {
  MockKeyStoreSet,
  MockCertificateStore,
  MockPublicKeyStore,
  MockPrivateKeyStore,
} from './lib/keyStores/testMocks';
export { KeyStoreError } from './lib/keyStores/KeyStoreError';
export { UnknownKeyError } from './lib/keyStores/UnknownKeyError';

// CMS
export * from './lib/crypto/cms/envelopedData'; // TODO: Remove
export { SessionKey } from './lib/SessionKey';
export { SessionKeyPair } from './lib/SessionKeyPair';
export { SignatureOptions } from './lib/crypto/cms/SignatureOptions';
export { CMSError } from './lib/crypto/cms/CMSError';

// RAMF
export { PayloadPlaintext as Payload } from './lib/messages/payloads/PayloadPlaintext';
export { RAMFError } from './lib/ramf/RAMFError';
export { RAMFSyntaxError } from './lib/ramf/RAMFSyntaxError';
export { MAX_RAMF_MESSAGE_LENGTH } from './lib/ramf/serialization';
export { RAMFMessage } from './lib/messages/RAMFMessage';
export { Recipient } from './lib/messages/Recipient';
export { Parcel } from './lib/messages/Parcel';
export { ServiceMessage } from './lib/messages/payloads/ServiceMessage';
export { Cargo } from './lib/messages/Cargo';
export { CargoMessageSet, CargoMessageSetItem } from './lib/messages/payloads/CargoMessageSet';
export { CargoCollectionAuthorization } from './lib/messages/CargoCollectionAuthorization';
export { CargoCollectionRequest } from './lib/messages/payloads/CargoCollectionRequest';
export { InvalidMessageError } from './lib/messages/InvalidMessageError';
export { RAMFValidationError } from './lib/ramf/RAMFValidationError';

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
export { PrivateGatewayManager } from './lib/nodes/managers/PrivateGatewayManager';
export { PrivateGateway } from './lib/nodes/PrivateGateway';
export { CargoMessageStream } from './lib/nodes/CargoMessageStream';
export { Channel } from './lib/nodes/channels/Channel';
export { GatewayChannel } from './lib/nodes/channels/GatewayChannel';
export { PrivateInternetGatewayChannel } from './lib/nodes/channels/PrivateInternetGatewayChannel';

//endregion

export { NodeCryptoOptions } from './lib/nodes/NodeCryptoOptions';
export { NodeConnectionParams } from './lib/nodes/NodeConnectionParams';
export * from './lib/nodes/errors';
export * from './lib/internetAddressing';
export { derDeserializeECDHPrivateKey } from './lib/crypto/keys/serialisation';
export { derDeserializeRSAPrivateKey } from './lib/crypto/keys/serialisation';
export { derDeserializeECDHPublicKey } from './lib/crypto/keys/serialisation';
export { derDeserializeRSAPublicKey } from './lib/crypto/keys/serialisation';
export { derSerializePrivateKey } from './lib/crypto/keys/serialisation';
export { derSerializePublicKey } from './lib/crypto/keys/serialisation';
