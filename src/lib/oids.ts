/**
 * ASN.1 Object Ids.
 */

export const COMMON_NAME = '2.5.4.3';

//region X.509 extensions
export const BASIC_CONSTRAINTS = '2.5.29.19';
export const AUTHORITY_KEY = '2.5.29.35';
export const SUBJECT_KEY = '2.5.29.14';
//endregion

//region CMS
export const CMS_DATA = '1.2.840.113549.1.7.1';
export const CMS_SIGNED_DATA = '1.2.840.113549.1.7.2';
export const CMS_ENVELOPED_DATA = '1.2.840.113549.1.7.3';
export const CMS_ATTR_CONTENT_TYPE = '1.2.840.113549.1.9.3';
export const CMS_ATTR_DIGEST = '1.2.840.113549.1.9.4';
//endregion

//region Relaynet
// Relaycorp's OID is 0.4.0.127.0.17
const RELAYCORP = '0.4.0.127.0.17';
const RELAYNET = `${RELAYCORP}.0`;

export const RELAYNET_ORIGINATOR_EPHEMERAL_CERT_SERIAL_NUMBER = `${RELAYNET}.1.0`;

const CLIENT_REGISTRATION_PREFIX = `${RELAYNET}.2`;
export const CRA = `${CLIENT_REGISTRATION_PREFIX}.0`;
export const CRA_COUNTERSIGNATURE = `${CLIENT_REGISTRATION_PREFIX}.1`;
//endregion
