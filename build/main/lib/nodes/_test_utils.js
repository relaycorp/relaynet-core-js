"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.StubNode = void 0;
const Node_1 = require("./Node");
class StubNode extends Node_1.Node {
    getPrivateKey() {
        return this.identityPrivateKey;
    }
    getKeyStores() {
        return this.keyStores;
    }
    getCryptoOptions() {
        return this.cryptoOptions;
    }
}
exports.StubNode = StubNode;
//# sourceMappingURL=_test_utils.js.map