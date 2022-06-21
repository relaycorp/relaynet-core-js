import { Node } from './Node';
export class Gateway extends Node {
    async getGSCVerifier(peerPrivateAddress, verifierClass) {
        const trustedPaths = await this.keyStores.certificateStore.retrieveAll(this.privateAddress, peerPrivateAddress);
        return new verifierClass(trustedPaths.map((p) => p.leafCertificate));
    }
}
//# sourceMappingURL=Gateway.js.map