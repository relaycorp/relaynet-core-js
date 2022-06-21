import { Crypto as BaseCrypto } from '@peculiar/webcrypto';
import { getCiphers } from 'crypto';
import { AwalaAesKwProvider } from './AwalaAesKwProvider';
export class AwalaCrypto extends BaseCrypto {
    constructor() {
        super();
        const doesNodejsSupportAesKw = getCiphers().includes('id-aes128-wrap');
        if (!doesNodejsSupportAesKw) {
            // This must be running on Electron, so let's use a pure JavaScript implementation of AES-KW:
            // https://github.com/relaycorp/relaynet-core-js/issues/367
            const providers = this.subtle.providers;
            const nodejsAesKwProvider = providers.get('AES-KW');
            providers.set(new AwalaAesKwProvider(nodejsAesKwProvider));
        }
    }
}
//# sourceMappingURL=AwalaCrypto.js.map