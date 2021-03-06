/* tslint:disable:max-classes-per-file */
import bufferToArray from 'buffer-to-arraybuffer';

import { SignatureOptions } from '../..';
import PayloadPlaintext from '../messages/payloads/PayloadPlaintext';
import RAMFMessage from '../messages/RAMFMessage';

export class StubPayload implements PayloadPlaintext {
  constructor(public readonly content: ArrayBuffer) {}

  public serialize(): ArrayBuffer {
    return this.content;
  }
}

export class StubMessage extends RAMFMessage<StubPayload> {
  public async serialize(
    // tslint:disable-next-line:variable-name
    _senderPrivateKey: CryptoKey,
    // tslint:disable-next-line:variable-name
    _signatureOptions?: SignatureOptions,
  ): Promise<ArrayBuffer> {
    return bufferToArray(Buffer.from('hi'));
  }

  protected deserializePayload(payloadPlaintext: ArrayBuffer): StubPayload {
    return new StubPayload(payloadPlaintext);
  }
}
