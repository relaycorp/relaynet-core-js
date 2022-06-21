"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const RAMFError_1 = __importDefault(require("./RAMFError"));
/** Syntax error detected in value meant to comply with RAMF spec. */
class RAMFSyntaxError extends RAMFError_1.default {
}
exports.default = RAMFSyntaxError;
//# sourceMappingURL=RAMFSyntaxError.js.map