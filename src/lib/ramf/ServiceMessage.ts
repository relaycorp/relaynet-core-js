import { Parser } from 'binary-parser';
import bufferToArray from 'buffer-to-arraybuffer';
import { SmartBuffer } from 'smart-buffer';
import Payload from './Payload';
import RAMFError from './RAMFError';

const MAX_TYPE_LENGTH = 2 ** 8 - 1; // 8-bit
const MAX_VALUE_LENGTH = 2 ** 32 - 1; // 32-bit

const PARSER = new Parser()
  .endianess('little')
  .uint8('messageTypeLength')
  .string('messageType', { length: 'messageTypeLength', encoding: 'utf8' })
  .uint32('messageLength')
  .buffer('message', { length: 'messageLength' });

/**
 * Service message as encapsulated in a parcel.
 */
export default class ServiceMessage implements Payload {
  /**
   * Initialize a service message from the `serialization`.
   *
   * @param serialization
   */
  public static deserialize(serialization: Buffer): ServiceMessage {
    // tslint:disable-next-line:no-let
    let messageParts;
    try {
      messageParts = PARSER.parse(serialization);
    } catch (error) {
      throw new RAMFError('Invalid service message serialization');
    }

    return new ServiceMessage(messageParts.messageType, messageParts.message);
  }

  constructor(readonly type: string, readonly value: Buffer) {}

  /**
   * Serialize service message.
   */
  public serialize(): ArrayBuffer {
    const typeLength = Buffer.byteLength(this.type);
    if (MAX_TYPE_LENGTH < typeLength) {
      throw new RAMFError('Service message type exceeds maximum length');
    }

    if (MAX_VALUE_LENGTH < this.value.length) {
      throw new RAMFError('Service message value exceeds maximum length');
    }

    const serialization = new SmartBuffer();
    serialization.writeInt8(typeLength);
    serialization.writeString(this.type);
    serialization.writeUInt32LE(this.value.length);
    serialization.writeBuffer(this.value);
    return bufferToArray(serialization.toBuffer());
  }
}
