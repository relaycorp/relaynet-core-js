import * as pkijs from 'pkijs';
export declare function deserializeContentInfo(derValue: ArrayBuffer): pkijs.ContentInfo;
interface PkiObjectConstructor<T extends pkijs.PkiObject = pkijs.PkiObject> {
    new (params: pkijs.PkiObjectParameters): T;
    readonly CLASS_NAME: string;
}
/**
 * Check that incoming object is instance of supplied type.
 *
 * @param obj Object to be validated
 * @param type Expected PKI type
 * @param targetName Name of the validated object
 */
export declare function assertPkiType<T extends pkijs.PkiObject>(obj: unknown, type: PkiObjectConstructor<T>, targetName: string): asserts obj is T;
export declare function assertUndefined(data: unknown, paramName?: string): asserts data;
export {};
