"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const RAMFError_1 = __importDefault(require("./RAMFError"));
/**
 * Error while validating RAMF message.
 */
class RAMFValidationError extends RAMFError_1.default {
}
exports.default = RAMFValidationError;
//# sourceMappingURL=RAMFValidationError.js.map