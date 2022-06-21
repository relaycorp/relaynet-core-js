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
Object.defineProperty(exports, "__esModule", { value: true });
exports.deserializeContentInfo = exports.serializeContentInfo = void 0;
const pkijs = __importStar(require("pkijs"));
const _utils_1 = require("../_utils");
function serializeContentInfo(content, contentType) {
    const contentInfo = new pkijs.ContentInfo({ content, contentType });
    return contentInfo.toSchema().toBER(false);
}
exports.serializeContentInfo = serializeContentInfo;
function deserializeContentInfo(contentInfoDer) {
    return new pkijs.ContentInfo({ schema: (0, _utils_1.derDeserialize)(contentInfoDer) });
}
exports.deserializeContentInfo = deserializeContentInfo;
//# sourceMappingURL=_test_utils.js.map