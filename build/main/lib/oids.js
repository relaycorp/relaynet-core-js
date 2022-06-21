"use strict";
/**
 * ASN.1 Object Ids.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.RELAYNET_OIDS = exports.CMS_OIDS = exports.SUBJECT_KEY = exports.AUTHORITY_KEY = exports.BASIC_CONSTRAINTS = exports.COMMON_NAME = void 0;
exports.COMMON_NAME = '2.5.4.3';
//region X.509 extensions
exports.BASIC_CONSTRAINTS = '2.5.29.19';
exports.AUTHORITY_KEY = '2.5.29.35';
exports.SUBJECT_KEY = '2.5.29.14';
//endregion
exports.CMS_OIDS = {
    ATTR_CONTENT_TYPE: '1.2.840.113549.1.9.3',
    ATTR_DIGEST: '1.2.840.113549.1.9.4',
    DATA: '1.2.840.113549.1.7.1',
    ENVELOPED_DATA: '1.2.840.113549.1.7.3',
    SIGNED_DATA: '1.2.840.113549.1.7.2',
};
//region Relaynet
const RELAYCORP = '0.4.0.127.0.17';
const RELAYNET = `${RELAYCORP}.0`;
const PRIVATE_NODE_REGISTRATION_PREFIX = `${RELAYNET}.2`;
const DETACHED_SIGNATURE_PREFIX = `${RELAYNET}.3`;
exports.RELAYNET_OIDS = {
    NODE_REGISTRATION: {
        AUTHORIZATION: `${PRIVATE_NODE_REGISTRATION_PREFIX}.0`,
        AUTHORIZATION_COUNTERSIGNATURE: `${PRIVATE_NODE_REGISTRATION_PREFIX}.1`,
    },
    ORIGINATOR_EPHEMERAL_CERT_SERIAL_NUMBER: `${RELAYNET}.1.0`,
    SIGNATURE: {
        PARCEL_COLLECTION_HANDSHAKE: `${DETACHED_SIGNATURE_PREFIX}.1`,
        PARCEL_DELIVERY: `${DETACHED_SIGNATURE_PREFIX}.0`,
    },
};
//endregion
//# sourceMappingURL=oids.js.map