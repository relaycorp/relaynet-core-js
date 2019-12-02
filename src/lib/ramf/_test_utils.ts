/* tslint:disable:max-classes-per-file */
import { Parser } from 'binary-parser';
import bufferToArray from 'buffer-to-arraybuffer';
import Message from './Message';
import { MessageSerializer } from './MessageSerializer';
import Payload from './Payload';

export const NON_ASCII_STRING = '❤こんにちは';

export class StubMessage extends Message<StubPayload> {}

export const STUB_MESSAGE_SERIALIZER = new MessageSerializer<StubMessage>(
  0x44,
  0x2
);

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

export const STUB_UUID4 = '56e95d8a-6be2-4020-bb36-5dd0da36c181';
