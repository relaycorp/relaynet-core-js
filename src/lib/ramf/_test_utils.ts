/* tslint:disable:max-classes-per-file */
import bufferToArray from 'buffer-to-arraybuffer';

import { SignatureOptions } from '../..';
import Message from '../messages/Message';

export const NON_ASCII_STRING = '❤こんにちは'; // Multi-byte characters

export class StubMessage extends Message {
  public async serialize(
    // tslint:disable-next-line:variable-name
    _senderPrivateKey: CryptoKey,
    // tslint:disable-next-line:variable-name
    _signatureOptions?: SignatureOptions,
  ): Promise<ArrayBuffer> {
    return bufferToArray(Buffer.from('hi'));
  }
}
