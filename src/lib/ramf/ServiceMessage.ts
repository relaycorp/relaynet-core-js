import { SmartBuffer } from 'smart-buffer';
import Payload from './Payload';
import RAMFError from './RAMFError';

const MAX_TYPE_LENGTH = 2 ** 8 - 1; // 8-bit
const MAX_VALUE_LENGTH = 2 ** 32 - 1; // 32-bit

/**
 * Service message as encapsulated in a parcel.
 */
export default class ServiceMessage extends Payload {
  constructor(readonly type: string, readonly value: Buffer) {
    super();
  }

  /**
   * Serialize service message.
   */
  public async serialize(): Promise<Buffer> {
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
    return serialization.toBuffer();
  }
}
