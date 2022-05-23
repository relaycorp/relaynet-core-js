import * as pkijs from 'pkijs';

import { derDeserialize } from '../_utils';
import CMSError from './CMSError';

export function deserializeContentInfo(derValue: ArrayBuffer): pkijs.ContentInfo {
  try {
    const asn1Value = derDeserialize(derValue);
    return new pkijs.ContentInfo({ schema: asn1Value });
  } catch (error) {
    throw new CMSError(error as Error, 'Could not deserialize CMS ContentInfo');
  }
}

interface PkiObjectConstructor<T extends pkijs.PkiObject = pkijs.PkiObject> {
  new (params: pkijs.PkiObjectParameters): T;
  readonly CLASS_NAME: string;
}

/**
 * Checks that incoming object is instance of supplied type
 * @param obj Object to be validated
 * @param type Expected PKI type
 * @param targetName Name of the validated object
 */
export function assertPkiType<T extends pkijs.PkiObject>(
  obj: unknown,
  type: PkiObjectConstructor<T>,
  targetName: string,
): asserts obj is T {
  if (!(obj && obj instanceof type)) {
    throw new TypeError(`Incorrect type of '${targetName}'. It should be '${type.CLASS_NAME}'`);
  }
}

export function assertUndefined(data: unknown, paramName?: string): asserts data {
  if (data === undefined) {
    throw new Error(`Required parameter ${paramName ? `'${paramName}'` : paramName} is missing`);
  }
}
