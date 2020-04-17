import * as asn1js from 'asn1js';

import { MAX_SDU_PLAINTEXT_LENGTH } from '../../ramf/serialization';
import InvalidMessageError from '../InvalidMessageError';
import Parcel from '../Parcel';
import PayloadPlaintext from './PayloadPlaintext';

/**
 * Number of octets needed to represent the type and length of an 8 MiB value in DER.
 */
const DER_TL_OVERHEAD_OCTETS = 5;

/**
 * Plaintext representation of the payload in a cargo message.
 *
 * That is, the set of RAMF messages the cargo contains.
 */
export default class CargoMessageSet implements PayloadPlaintext {
  /**
   * Maximum number of octets for any serialized message to be included in a cargo.
   *
   * This is the result of subtracting the TLVs for the SET and BIT STRING values from the maximum
   * size of an SDU to be encrypted.
   */
  public static readonly MAX_MESSAGE_LENGTH =
    MAX_SDU_PLAINTEXT_LENGTH - DER_TL_OVERHEAD_OCTETS * 2 - 1;

  public static deserialize(serialization: ArrayBuffer): CargoMessageSet {
    const result = asn1js.verifySchema(serialization, CargoMessageSet.ASN1_SCHEMA);
    if (!result.verified) {
      throw new InvalidMessageError('Serialization is not a valid CargoMessageSet');
    }
    const messageSet: readonly asn1js.BitString[] = (result.result as any).message_set || [];
    const messages = messageSet.map(v => v.valueBlock.valueHex);
    return new CargoMessageSet(new Set(messages));
  }

  public static async *batchMessagesSerialized(
    messagesSerialized: AsyncIterable<ArrayBuffer>,
  ): AsyncIterable<ArrayBuffer> {
    // tslint:disable-next-line:readonly-array no-let
    let currentBatch: Set<ArrayBuffer> = new Set([]);
    // tslint:disable-next-line:no-let
    let availableOctetsInCurrentBatch = MAX_SDU_PLAINTEXT_LENGTH - DER_TL_OVERHEAD_OCTETS;

    for await (const messageSerialized of messagesSerialized) {
      if (CargoMessageSet.MAX_MESSAGE_LENGTH < messageSerialized.byteLength) {
        throw new InvalidMessageError(
          `Cargo messages must not exceed ${CargoMessageSet.MAX_MESSAGE_LENGTH} octets ` +
            `(got one with ${messageSerialized.byteLength} octets)`,
        );
      }

      const messageTlvLength = DER_TL_OVERHEAD_OCTETS + messageSerialized.byteLength;
      const messageFitsInCurrentBatch = messageTlvLength <= availableOctetsInCurrentBatch;
      if (messageFitsInCurrentBatch) {
        currentBatch.add(messageSerialized);
        availableOctetsInCurrentBatch -= messageTlvLength;
      } else {
        const cargoMessageSet = new CargoMessageSet(currentBatch);
        yield cargoMessageSet.serialize();

        currentBatch = new Set([messageSerialized]);
        availableOctetsInCurrentBatch = MAX_SDU_PLAINTEXT_LENGTH - messageTlvLength;
      }
    }

    if (currentBatch.size) {
      const cargoMessageSet = new CargoMessageSet(currentBatch);
      yield cargoMessageSet.serialize();
    }
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

  constructor(public readonly messages: Set<ArrayBuffer>) {}

  public serialize(): ArrayBuffer {
    const messagesSerialized = Array.from(this.messages).map(
      m => new asn1js.BitString({ valueHex: m }),
    );
    const set = new asn1js.Set();
    // tslint:disable-next-line:no-object-mutation
    set.valueBlock.value = messagesSerialized;
    return set.toBER(false);
  }

  public async *deserializeMessages(): AsyncIterableIterator<Parcel> {
    for (const message of this.messages) {
      try {
        yield Parcel.deserialize(message);
      } catch (error) {
        throw new InvalidMessageError(error, 'Invalid message found');
      }
    }
  }
}
