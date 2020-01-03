/* tslint:disable:max-classes-per-file */
import bufferToArray from 'buffer-to-arraybuffer';

import Message from './Message';
import Payload from './Payload';

export const NON_ASCII_STRING = '❤こんにちは'; // Multi-byte characters

export class StubMessage extends Message<StubPayload> {
  // tslint:disable-next-line:variable-name
  public unwrapPayload(_privateKey: CryptoKey): StubPayload {
    return new StubPayload();
  }
}

export class StubPayload implements Payload {
  public static readonly BUFFER = bufferToArray(Buffer.from('Hi'));

  public serialize(): ArrayBuffer {
    return StubPayload.BUFFER;
  }
}
