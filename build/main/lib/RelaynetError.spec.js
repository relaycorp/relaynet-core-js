"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const RelaynetError_1 = __importDefault(require("./RelaynetError"));
test('.name should be taken from the name of the class', () => {
    class FooError extends RelaynetError_1.default {
    }
    const error = new FooError('Winter is coming');
    expect(error.name).toBe('FooError');
});
//# sourceMappingURL=RelaynetError.spec.js.map