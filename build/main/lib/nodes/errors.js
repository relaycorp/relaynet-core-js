"use strict";
// tslint:disable:max-classes-per-file
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.InvalidPublicNodeConnectionParams = exports.NodeError = void 0;
const RelaynetError_1 = __importDefault(require("../RelaynetError"));
class NodeError extends RelaynetError_1.default {
}
exports.NodeError = NodeError;
class InvalidPublicNodeConnectionParams extends NodeError {
}
exports.InvalidPublicNodeConnectionParams = InvalidPublicNodeConnectionParams;
//# sourceMappingURL=errors.js.map