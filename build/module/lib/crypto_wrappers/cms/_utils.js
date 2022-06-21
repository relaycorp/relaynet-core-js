import * as pkijs from 'pkijs';
import { derDeserialize } from '../_utils';
import CMSError from './CMSError';
export function deserializeContentInfo(derValue) {
    try {
        const asn1Value = derDeserialize(derValue);
        return new pkijs.ContentInfo({ schema: asn1Value });
    }
    catch (error) {
        throw new CMSError(error, 'Could not deserialize CMS ContentInfo');
    }
}
/**
 * Check that incoming object is instance of supplied type.
 *
 * @param obj Object to be validated
 * @param type Expected PKI type
 * @param targetName Name of the validated object
 */
export function assertPkiType(obj, type, targetName) {
    if (!(obj && obj instanceof type)) {
        throw new TypeError(`Incorrect type of '${targetName}'. It should be '${type.CLASS_NAME}'`);
    }
}
export function assertUndefined(data, paramName) {
    if (data === undefined) {
        throw new Error(`Required parameter ${paramName ? `'${paramName}'` : paramName} is missing`);
    }
}
//# sourceMappingURL=_utils.js.map