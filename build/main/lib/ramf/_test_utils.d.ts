import { SignatureOptions } from '../..';
import PayloadPlaintext from '../messages/payloads/PayloadPlaintext';
import RAMFMessage from '../messages/RAMFMessage';
export declare class StubPayload implements PayloadPlaintext {
    readonly content: ArrayBuffer;
    constructor(content: ArrayBuffer);
    serialize(): ArrayBuffer;
}
export declare class StubMessage extends RAMFMessage<StubPayload> {
    serialize(_senderPrivateKey: CryptoKey, _signatureOptions?: SignatureOptions): Promise<ArrayBuffer>;
    protected deserializePayload(payloadPlaintext: ArrayBuffer): StubPayload;
}
