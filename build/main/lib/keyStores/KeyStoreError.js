"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.KeyStoreError = void 0;
const RelaynetError_1 = __importDefault(require("../RelaynetError"));
/**
 * Error thrown when there was a failure in the communication with the backing service.
 */
class KeyStoreError extends RelaynetError_1.default {
}
exports.KeyStoreError = KeyStoreError;
//# sourceMappingURL=KeyStoreError.js.map