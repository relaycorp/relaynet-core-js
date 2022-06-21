"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const RelaynetError_1 = __importDefault(require("../RelaynetError"));
/**
 * Error while processing message.
 */
class InvalidMessageError extends RelaynetError_1.default {
}
exports.default = InvalidMessageError;
//# sourceMappingURL=InvalidMessageError.js.map