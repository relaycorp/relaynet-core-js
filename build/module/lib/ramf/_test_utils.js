/* tslint:disable:max-classes-per-file */
import bufferToArray from 'buffer-to-arraybuffer';
import RAMFMessage from '../messages/RAMFMessage';
export class StubPayload {
    content;
    constructor(content) {
        this.content = content;
    }
    serialize() {
        return this.content;
    }
}
export class StubMessage extends RAMFMessage {
    async serialize(
    // tslint:disable-next-line:variable-name
    _senderPrivateKey, 
    // tslint:disable-next-line:variable-name
    _signatureOptions) {
        return bufferToArray(Buffer.from('hi'));
    }
    deserializePayload(payloadPlaintext) {
        return new StubPayload(payloadPlaintext);
    }
}
//# sourceMappingURL=_test_utils.js.map