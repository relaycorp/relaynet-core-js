import { Parser } from 'binary-parser';
import bufferToArray from 'buffer-to-arraybuffer';

import RAMFError from '../../ramf/RAMFError';
import InvalidMessageError from '../InvalidMessageError';
import PayloadPlaintext from './PayloadPlaintext';

const MAX_TYPE_LENGTH = 2 ** 8 - 1; // 8-bit
const MAX_VALUE_LENGTH = 2 ** 23 - 1; // 23-bit

const PARSER = new Parser()
  .endianess('little')
  .uint8('messageTypeLength')
  .string('messageType', { length: 'messageTypeLength', encoding: 'utf8' })
  .uint32('messageLength')
  .buffer('message', { length: 'messageLength' });

/**
 * Service message as encapsulated in a parcel.
 */
export default class ServiceMessage implements PayloadPlaintext {
  /**
   * Maximum length of the service message serialized.
   */
  public static readonly MAX_LENGTH = 8256501;

  /**
   * Initialize a service message from the `serialization`.
   *
   * @param serialization
   */
  public static deserialize(serialization: ArrayBuffer): ServiceMessage {
    const serializationBuffer = Buffer.from(serialization);
    // tslint:disable-next-line:no-let
    let messageParts;
    try {
      messageParts = PARSER.parse(serializationBuffer);
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
    // TODO: Validate instance fields in the constructor instead.

    const typeLength = Buffer.byteLength(this.type);
    if (MAX_TYPE_LENGTH < typeLength) {
      throw new RAMFError('Service message type exceeds maximum length');
    }

    if (MAX_VALUE_LENGTH < this.value.length) {
      throw new RAMFError('Service message value exceeds maximum length');
    }

    const serializationLength = 1 + typeLength + 4 + this.value.length;
    if (ServiceMessage.MAX_LENGTH < serializationLength) {
      throw new InvalidMessageError(
        `Service message must not exceed ${ServiceMessage.MAX_LENGTH} octets ` +
          `(got ${serializationLength} octets)`,
      );
    }

    const serialization = Buffer.allocUnsafe(serializationLength);
    serialization.writeUInt8(typeLength, 0);
    serialization.write(this.type, 1);
    serialization.writeUInt32LE(this.value.length, 1 + typeLength);
    this.value.copy(serialization, 1 + typeLength + 4);
    return bufferToArray(serialization);
  }
}
