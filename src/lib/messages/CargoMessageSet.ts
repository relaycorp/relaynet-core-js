import * as asn1js from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';

import { deserializeDer } from '../crypto_wrappers/_utils';
import InvalidMessageError from './InvalidMessageError';
import PayloadPlaintext from './PayloadPlaintext';

/**
 * Plaintext representation of the payload in a cargo message.
 *
 * That is, the set of RAMF messages the cargo contains.
 */
export default class CargoMessageSet implements PayloadPlaintext {
  public static deserialize(serialization: Buffer): CargoMessageSet {
    const asn1Value = deserializeDer(bufferToArray(serialization));
    const result = asn1js.compareSchema(asn1Value, asn1Value, CargoMessageSet.ASN1_SCHEMA);
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

  constructor(public readonly messages: ReadonlySet<Buffer>) {}

  public serialize(): ArrayBuffer {
    const messagesSerialized = Array.from(this.messages).map(
      m => new asn1js.BitString({ valueHex: bufferToArray(m) }),
    );
    const set = new asn1js.Set();
    // tslint:disable-next-line:no-object-mutation
    set.valueBlock.value = messagesSerialized;
    return set.toBER(false);
  }
}
