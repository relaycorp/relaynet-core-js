import { OctetString, Primitive, verifySchema, VisibleString } from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';
import { TextDecoder } from 'util';

import { makeHeterogeneousSequenceSchema, makeImplicitlyTaggedSequence } from '../../asn1';
import { InvalidMessageError } from '../InvalidMessageError';
import { PayloadPlaintext } from './PayloadPlaintext';

/**
 * Service message as encapsulated in a parcel.
 */
export class ServiceMessage implements PayloadPlaintext {
  /**
   * Initialize a service message from the `serialization`.
   *
   * @param serialization
   */
  public static deserialize(serialization: ArrayBuffer): ServiceMessage {
    const result = verifySchema(serialization, ServiceMessage.SCHEMA);
    if (!result.verified) {
      throw new InvalidMessageError('Invalid service message serialization');
    }
    const messageASN1 = (result.result as any).ServiceMessage;
    const type = new TextDecoder().decode(messageASN1.type.valueBlock.valueHex);
    const content = Buffer.from(messageASN1.content.valueBlock.valueHex);
    return new ServiceMessage(type, content);
  }

  private static readonly SCHEMA = makeHeterogeneousSequenceSchema('ServiceMessage', [
    new Primitive({ name: 'type' }),
    new Primitive({ name: 'content' }),
  ]);

  constructor(
    readonly type: string,
    readonly content: Buffer,
  ) {}

  /**
   * Serialize service message.
   */
  public serialize(): ArrayBuffer {
    const typeASN1 = new VisibleString({ value: this.type });
    const contentASN1 = new OctetString({ valueHex: bufferToArray(this.content) });
    return makeImplicitlyTaggedSequence(typeASN1, contentASN1).toBER();
  }
}
