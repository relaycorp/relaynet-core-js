/* tslint:disable:max-classes-per-file */
import { Parser } from 'binary-parser';
import bufferToArray from 'buffer-to-arraybuffer';

import Message from './Message';
import { MessageSerializer } from './MessageSerializer';
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

export const STUB_MESSAGE_SERIALIZER = new MessageSerializer<StubMessage>(StubMessage, 0x44, 0x2);

export class StubPayload implements Payload {
  public static readonly BUFFER = bufferToArray(Buffer.from('Hi'));

  public serialize(): ArrayBuffer {
    return StubPayload.BUFFER;
  }
}

export const MESSAGE_PARSER = new Parser()
  .endianess('little')
  .string('magic', { length: 8, assert: 'Relaynet' })
  .uint8('concreteMessageSignature')
  .uint8('concreteMessageVersion')
  .uint16('recipientAddressLength')
  .string('recipientAddress', { length: 'recipientAddressLength' })
  .uint8('messageIdLength')
  .string('messageId', { length: 'messageIdLength', encoding: 'ascii' })
  .uint32('date')
  .buffer('ttlBuffer', { length: 3 })
  .uint32('payloadLength')
  .buffer('payload', { length: 'payloadLength' })
  .uint16('signatureLength')
  .buffer('signature', { length: 'signatureLength' });
