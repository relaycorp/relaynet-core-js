"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const RelaynetError_1 = __importDefault(require("../RelaynetError"));
/**
 * Error thrown when a peer references an invalid key.
 */
class UnknownKeyError extends RelaynetError_1.default {
}
exports.default = UnknownKeyError;
//# sourceMappingURL=UnknownKeyError.js.map