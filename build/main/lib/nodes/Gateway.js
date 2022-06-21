"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Gateway = void 0;
const Node_1 = require("./Node");
class Gateway extends Node_1.Node {
    async getGSCVerifier(peerPrivateAddress, verifierClass) {
        const trustedPaths = await this.keyStores.certificateStore.retrieveAll(this.privateAddress, peerPrivateAddress);
        return new verifierClass(trustedPaths.map((p) => p.leafCertificate));
    }
}
exports.Gateway = Gateway;
//# sourceMappingURL=Gateway.js.map