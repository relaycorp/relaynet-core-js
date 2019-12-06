/* tslint:disable:max-classes-per-file */
import bufferToArray from 'buffer-to-arraybuffer';

import Message from './Message';
import Payload from './Payload';

export const NON_ASCII_STRING = '❤こんにちは'; // Multi-byte characters

export class StubMessage extends Message {
  // @ts-ignore
  // tslint:disable-next-line:readonly-keyword
  public payloadPlaintext: ArrayBuffer;

  public exportPayload(): ArrayBuffer {
    return this.payloadPlaintext;
  }

  protected importPayload(payloadPlaintext: ArrayBuffer): void {
    // tslint:disable-next-line:no-object-mutation
    this.payloadPlaintext = payloadPlaintext;
  }
}

export class StubPayload implements Payload {
  public static readonly BUFFER = bufferToArray(Buffer.from('Hi'));

  public serialize(): ArrayBuffer {
    return StubPayload.BUFFER;
  }
}
