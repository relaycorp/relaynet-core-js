"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.StubMessage = exports.StubPayload = void 0;
/* tslint:disable:max-classes-per-file */
const buffer_to_arraybuffer_1 = __importDefault(require("buffer-to-arraybuffer"));
const RAMFMessage_1 = __importDefault(require("../messages/RAMFMessage"));
class StubPayload {
    constructor(content) {
        this.content = content;
    }
    serialize() {
        return this.content;
    }
}
exports.StubPayload = StubPayload;
class StubMessage extends RAMFMessage_1.default {
    async serialize(
    // tslint:disable-next-line:variable-name
    _senderPrivateKey, 
    // tslint:disable-next-line:variable-name
    _signatureOptions) {
        return (0, buffer_to_arraybuffer_1.default)(Buffer.from('hi'));
    }
    deserializePayload(payloadPlaintext) {
        return new StubPayload(payloadPlaintext);
    }
}
exports.StubMessage = StubMessage;
//# sourceMappingURL=_test_utils.js.map