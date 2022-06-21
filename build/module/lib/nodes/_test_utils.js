import { Node } from './Node';
export class StubNode extends Node {
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
//# sourceMappingURL=_test_utils.js.map