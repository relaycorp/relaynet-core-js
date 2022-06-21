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
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.assertUndefined = exports.assertPkiType = exports.deserializeContentInfo = void 0;
const pkijs = __importStar(require("pkijs"));
const _utils_1 = require("../_utils");
const CMSError_1 = __importDefault(require("./CMSError"));
function deserializeContentInfo(derValue) {
    try {
        const asn1Value = (0, _utils_1.derDeserialize)(derValue);
        return new pkijs.ContentInfo({ schema: asn1Value });
    }
    catch (error) {
        throw new CMSError_1.default(error, 'Could not deserialize CMS ContentInfo');
    }
}
exports.deserializeContentInfo = deserializeContentInfo;
/**
 * Check that incoming object is instance of supplied type.
 *
 * @param obj Object to be validated
 * @param type Expected PKI type
 * @param targetName Name of the validated object
 */
function assertPkiType(obj, type, targetName) {
    if (!(obj && obj instanceof type)) {
        throw new TypeError(`Incorrect type of '${targetName}'. It should be '${type.CLASS_NAME}'`);
    }
}
exports.assertPkiType = assertPkiType;
function assertUndefined(data, paramName) {
    if (data === undefined) {
        throw new Error(`Required parameter ${paramName ? `'${paramName}'` : paramName} is missing`);
    }
}
exports.assertUndefined = assertUndefined;
//# sourceMappingURL=_utils.js.map