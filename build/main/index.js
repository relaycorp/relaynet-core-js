"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.PrivateGateway = exports.PrivateGatewayManager = exports.Gateway = exports.GatewayManager = exports.EndpointManager = exports.Endpoint = exports.CertificateRotation = exports.PrivateNodeRegistrationRequest = exports.PrivateNodeRegistration = exports.PrivateNodeRegistrationAuthorization = exports.ParcelDelivery = exports.ParcelCollection = exports.HandshakeResponse = exports.HandshakeChallenge = exports.StreamingMode = exports.RAMFValidationError = exports.InvalidMessageError = exports.CargoMessageSet = exports.CargoCollectionRequest = exports.CargoCollectionAuthorization = exports.Cargo = exports.ServiceMessage = exports.Parcel = exports.RecipientAddressType = exports.RAMFMessage = exports.MAX_RAMF_MESSAGE_LENGTH = exports.RAMFSyntaxError = exports.RAMFError = exports.CMSError = exports.SessionKeyPair = exports.UnknownKeyError = exports.KeyStoreError = exports.CertificateStore = exports.PrivateKeyStore = exports.CertificateError = exports.CertificationPath = exports.Certificate = exports.getPrivateAddressFromIdentityKey = exports.getRSAPublicKeyFromPrivate = exports.getPublicKeyDigestHex = exports.getPublicKeyDigest = exports.generateRSAKeyPair = exports.generateECDHKeyPair = exports.derSerializePublicKey = exports.derSerializePrivateKey = exports.derDeserializeRSAPublicKey = exports.derDeserializeRSAPrivateKey = exports.derDeserializeECDHPublicKey = exports.derDeserializeECDHPrivateKey = exports.RelaynetError = void 0;
exports.PublicNodeConnectionParams = exports.PrivatePublicGatewayChannel = exports.GatewayChannel = exports.Channel = void 0;
//region Configure PKI.js
const pkijs_1 = require("pkijs");
const AwalaCrypto_1 = require("./lib/crypto_wrappers/webcrypto/AwalaCrypto");
const crypto = new AwalaCrypto_1.AwalaCrypto();
const cryptoEngine = new pkijs_1.CryptoEngine({
    crypto,
    name: 'nodeEngine',
    subtle: crypto.subtle,
});
(0, pkijs_1.setEngine)('nodeEngine', crypto, cryptoEngine);
//endregion
//region Exports
var RelaynetError_1 = require("./lib/RelaynetError");
Object.defineProperty(exports, "RelaynetError", { enumerable: true, get: function () { return __importDefault(RelaynetError_1).default; } });
var keys_1 = require("./lib/crypto_wrappers/keys");
Object.defineProperty(exports, "derDeserializeECDHPrivateKey", { enumerable: true, get: function () { return keys_1.derDeserializeECDHPrivateKey; } });
Object.defineProperty(exports, "derDeserializeECDHPublicKey", { enumerable: true, get: function () { return keys_1.derDeserializeECDHPublicKey; } });
Object.defineProperty(exports, "derDeserializeRSAPrivateKey", { enumerable: true, get: function () { return keys_1.derDeserializeRSAPrivateKey; } });
Object.defineProperty(exports, "derDeserializeRSAPublicKey", { enumerable: true, get: function () { return keys_1.derDeserializeRSAPublicKey; } });
Object.defineProperty(exports, "derSerializePrivateKey", { enumerable: true, get: function () { return keys_1.derSerializePrivateKey; } });
Object.defineProperty(exports, "derSerializePublicKey", { enumerable: true, get: function () { return keys_1.derSerializePublicKey; } });
Object.defineProperty(exports, "generateECDHKeyPair", { enumerable: true, get: function () { return keys_1.generateECDHKeyPair; } });
Object.defineProperty(exports, "generateRSAKeyPair", { enumerable: true, get: function () { return keys_1.generateRSAKeyPair; } });
Object.defineProperty(exports, "getPublicKeyDigest", { enumerable: true, get: function () { return keys_1.getPublicKeyDigest; } });
Object.defineProperty(exports, "getPublicKeyDigestHex", { enumerable: true, get: function () { return keys_1.getPublicKeyDigestHex; } });
Object.defineProperty(exports, "getRSAPublicKeyFromPrivate", { enumerable: true, get: function () { return keys_1.getRSAPublicKeyFromPrivate; } });
Object.defineProperty(exports, "getPrivateAddressFromIdentityKey", { enumerable: true, get: function () { return keys_1.getPrivateAddressFromIdentityKey; } });
__exportStar(require("./lib/cargoRelay"), exports);
// PKI
var Certificate_1 = require("./lib/crypto_wrappers/x509/Certificate");
Object.defineProperty(exports, "Certificate", { enumerable: true, get: function () { return __importDefault(Certificate_1).default; } });
var CertificationPath_1 = require("./lib/pki/CertificationPath");
Object.defineProperty(exports, "CertificationPath", { enumerable: true, get: function () { return CertificationPath_1.CertificationPath; } });
var CertificateError_1 = require("./lib/crypto_wrappers/x509/CertificateError");
Object.defineProperty(exports, "CertificateError", { enumerable: true, get: function () { return __importDefault(CertificateError_1).default; } });
__exportStar(require("./lib/pki/issuance"), exports);
// Key stores
var PrivateKeyStore_1 = require("./lib/keyStores/PrivateKeyStore");
Object.defineProperty(exports, "PrivateKeyStore", { enumerable: true, get: function () { return PrivateKeyStore_1.PrivateKeyStore; } });
__exportStar(require("./lib/keyStores/PublicKeyStore"), exports);
var CertificateStore_1 = require("./lib/keyStores/CertificateStore");
Object.defineProperty(exports, "CertificateStore", { enumerable: true, get: function () { return CertificateStore_1.CertificateStore; } });
__exportStar(require("./lib/keyStores/testMocks"), exports);
var KeyStoreError_1 = require("./lib/keyStores/KeyStoreError");
Object.defineProperty(exports, "KeyStoreError", { enumerable: true, get: function () { return KeyStoreError_1.KeyStoreError; } });
var UnknownKeyError_1 = require("./lib/keyStores/UnknownKeyError");
Object.defineProperty(exports, "UnknownKeyError", { enumerable: true, get: function () { return __importDefault(UnknownKeyError_1).default; } });
// CMS
__exportStar(require("./lib/crypto_wrappers/cms/envelopedData"), exports); // TODO: Remove
var SessionKeyPair_1 = require("./lib/SessionKeyPair");
Object.defineProperty(exports, "SessionKeyPair", { enumerable: true, get: function () { return SessionKeyPair_1.SessionKeyPair; } });
var CMSError_1 = require("./lib/crypto_wrappers/cms/CMSError");
Object.defineProperty(exports, "CMSError", { enumerable: true, get: function () { return __importDefault(CMSError_1).default; } });
var RAMFError_1 = require("./lib/ramf/RAMFError");
Object.defineProperty(exports, "RAMFError", { enumerable: true, get: function () { return __importDefault(RAMFError_1).default; } });
var RAMFSyntaxError_1 = require("./lib/ramf/RAMFSyntaxError");
Object.defineProperty(exports, "RAMFSyntaxError", { enumerable: true, get: function () { return __importDefault(RAMFSyntaxError_1).default; } });
var serialization_1 = require("./lib/ramf/serialization");
Object.defineProperty(exports, "MAX_RAMF_MESSAGE_LENGTH", { enumerable: true, get: function () { return serialization_1.MAX_RAMF_MESSAGE_LENGTH; } });
var RAMFMessage_1 = require("./lib/messages/RAMFMessage");
Object.defineProperty(exports, "RAMFMessage", { enumerable: true, get: function () { return __importDefault(RAMFMessage_1).default; } });
var RecipientAddressType_1 = require("./lib/messages/RecipientAddressType");
Object.defineProperty(exports, "RecipientAddressType", { enumerable: true, get: function () { return RecipientAddressType_1.RecipientAddressType; } });
var Parcel_1 = require("./lib/messages/Parcel");
Object.defineProperty(exports, "Parcel", { enumerable: true, get: function () { return __importDefault(Parcel_1).default; } });
var ServiceMessage_1 = require("./lib/messages/payloads/ServiceMessage");
Object.defineProperty(exports, "ServiceMessage", { enumerable: true, get: function () { return __importDefault(ServiceMessage_1).default; } });
var Cargo_1 = require("./lib/messages/Cargo");
Object.defineProperty(exports, "Cargo", { enumerable: true, get: function () { return __importDefault(Cargo_1).default; } });
var CargoCollectionAuthorization_1 = require("./lib/messages/CargoCollectionAuthorization");
Object.defineProperty(exports, "CargoCollectionAuthorization", { enumerable: true, get: function () { return CargoCollectionAuthorization_1.CargoCollectionAuthorization; } });
var CargoCollectionRequest_1 = require("./lib/messages/payloads/CargoCollectionRequest");
Object.defineProperty(exports, "CargoCollectionRequest", { enumerable: true, get: function () { return CargoCollectionRequest_1.CargoCollectionRequest; } });
var CargoMessageSet_1 = require("./lib/messages/payloads/CargoMessageSet");
Object.defineProperty(exports, "CargoMessageSet", { enumerable: true, get: function () { return __importDefault(CargoMessageSet_1).default; } });
var InvalidMessageError_1 = require("./lib/messages/InvalidMessageError");
Object.defineProperty(exports, "InvalidMessageError", { enumerable: true, get: function () { return __importDefault(InvalidMessageError_1).default; } });
var RAMFValidationError_1 = require("./lib/ramf/RAMFValidationError");
Object.defineProperty(exports, "RAMFValidationError", { enumerable: true, get: function () { return __importDefault(RAMFValidationError_1).default; } });
// Control messages
__exportStar(require("./lib/messages/ParcelCollectionAck"), exports);
var StreamingMode_1 = require("./lib/bindings/gsc/StreamingMode");
Object.defineProperty(exports, "StreamingMode", { enumerable: true, get: function () { return StreamingMode_1.StreamingMode; } });
var HandshakeChallenge_1 = require("./lib/bindings/gsc/HandshakeChallenge");
Object.defineProperty(exports, "HandshakeChallenge", { enumerable: true, get: function () { return HandshakeChallenge_1.HandshakeChallenge; } });
var HandshakeResponse_1 = require("./lib/bindings/gsc/HandshakeResponse");
Object.defineProperty(exports, "HandshakeResponse", { enumerable: true, get: function () { return HandshakeResponse_1.HandshakeResponse; } });
var ParcelCollection_1 = require("./lib/bindings/gsc/ParcelCollection");
Object.defineProperty(exports, "ParcelCollection", { enumerable: true, get: function () { return ParcelCollection_1.ParcelCollection; } });
var ParcelDelivery_1 = require("./lib/bindings/gsc/ParcelDelivery");
Object.defineProperty(exports, "ParcelDelivery", { enumerable: true, get: function () { return ParcelDelivery_1.ParcelDelivery; } });
var PrivateNodeRegistrationAuthorization_1 = require("./lib/bindings/gsc/PrivateNodeRegistrationAuthorization");
Object.defineProperty(exports, "PrivateNodeRegistrationAuthorization", { enumerable: true, get: function () { return PrivateNodeRegistrationAuthorization_1.PrivateNodeRegistrationAuthorization; } });
var PrivateNodeRegistration_1 = require("./lib/bindings/gsc/PrivateNodeRegistration");
Object.defineProperty(exports, "PrivateNodeRegistration", { enumerable: true, get: function () { return PrivateNodeRegistration_1.PrivateNodeRegistration; } });
var PrivateNodeRegistrationRequest_1 = require("./lib/bindings/gsc/PrivateNodeRegistrationRequest");
Object.defineProperty(exports, "PrivateNodeRegistrationRequest", { enumerable: true, get: function () { return PrivateNodeRegistrationRequest_1.PrivateNodeRegistrationRequest; } });
var CertificateRotation_1 = require("./lib/messages/CertificateRotation");
Object.defineProperty(exports, "CertificateRotation", { enumerable: true, get: function () { return CertificateRotation_1.CertificateRotation; } });
__exportStar(require("./lib/messages/bindings/signatures"), exports);
// Nodes
var Endpoint_1 = require("./lib/nodes/Endpoint");
Object.defineProperty(exports, "Endpoint", { enumerable: true, get: function () { return Endpoint_1.Endpoint; } });
var EndpointManager_1 = require("./lib/nodes/managers/EndpointManager");
Object.defineProperty(exports, "EndpointManager", { enumerable: true, get: function () { return EndpointManager_1.EndpointManager; } });
var GatewayManager_1 = require("./lib/nodes/managers/GatewayManager");
Object.defineProperty(exports, "GatewayManager", { enumerable: true, get: function () { return GatewayManager_1.GatewayManager; } });
var Gateway_1 = require("./lib/nodes/Gateway");
Object.defineProperty(exports, "Gateway", { enumerable: true, get: function () { return Gateway_1.Gateway; } });
var PrivateGatewayManager_1 = require("./lib/nodes/managers/PrivateGatewayManager");
Object.defineProperty(exports, "PrivateGatewayManager", { enumerable: true, get: function () { return PrivateGatewayManager_1.PrivateGatewayManager; } });
var PrivateGateway_1 = require("./lib/nodes/PrivateGateway");
Object.defineProperty(exports, "PrivateGateway", { enumerable: true, get: function () { return PrivateGateway_1.PrivateGateway; } });
var Channel_1 = require("./lib/nodes/channels/Channel");
Object.defineProperty(exports, "Channel", { enumerable: true, get: function () { return Channel_1.Channel; } });
var GatewayChannel_1 = require("./lib/nodes/channels/GatewayChannel");
Object.defineProperty(exports, "GatewayChannel", { enumerable: true, get: function () { return GatewayChannel_1.GatewayChannel; } });
var PrivatePublicGatewayChannel_1 = require("./lib/nodes/channels/PrivatePublicGatewayChannel");
Object.defineProperty(exports, "PrivatePublicGatewayChannel", { enumerable: true, get: function () { return PrivatePublicGatewayChannel_1.PrivatePublicGatewayChannel; } });
var PublicNodeConnectionParams_1 = require("./lib/nodes/PublicNodeConnectionParams");
Object.defineProperty(exports, "PublicNodeConnectionParams", { enumerable: true, get: function () { return PublicNodeConnectionParams_1.PublicNodeConnectionParams; } });
__exportStar(require("./lib/nodes/errors"), exports);
__exportStar(require("./lib/publicAddressing"), exports);
//# sourceMappingURL=index.js.map