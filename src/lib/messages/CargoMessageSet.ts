import * as asn1js from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';

import InvalidMessageError from './InvalidMessageError';
import Parcel from './Parcel';
import PayloadPlaintext from './PayloadPlaintext';

/**
 * Plaintext representation of the payload in a cargo message.
 *
 * That is, the set of RAMF messages the cargo contains.
 */
export default class CargoMessageSet implements PayloadPlaintext {
  public static deserialize(serialization: ArrayBuffer): CargoMessageSet {
    const result = asn1js.verifySchema(serialization, CargoMessageSet.ASN1_SCHEMA);
    if (!result.verified) {
      throw new InvalidMessageError('Serialization is not a valid CargoMessageSet');
    }
    const messageSet: readonly asn1js.BitString[] = (result.result as any).message_set || [];
    const messages: readonly Buffer[] = messageSet.map(v => Buffer.from(v.valueBlock.valueHex));
    return new CargoMessageSet(new Set(messages));
  }

  protected static readonly ASN1_SCHEMA = new asn1js.Set({
    name: 'CargoMessages',
    // @ts-ignore
    value: [
      new asn1js.Repeated({
        name: 'message_set',
        // @ts-ignore
        value: new asn1js.BitString({ name: 'message' }),
      }),
    ],
  });

  constructor(public readonly messages: Set<Buffer>) {}

  public serialize(): ArrayBuffer {
    const messagesSerialized = Array.from(this.messages).map(
      m => new asn1js.BitString({ valueHex: bufferToArray(m) }),
    );
    const set = new asn1js.Set();
    // tslint:disable-next-line:no-object-mutation
    set.valueBlock.value = messagesSerialized;
    return set.toBER(false);
  }

  public async *deserializeMessages(): AsyncIterableIterator<Parcel> {
    for (const message of this.messages) {
      try {
        yield Parcel.deserialize(bufferToArray(message));
      } catch (error) {
        throw new InvalidMessageError(error, 'Invalid message found');
      }
    }
  }
}
