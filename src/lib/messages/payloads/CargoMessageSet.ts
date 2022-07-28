import * as asn1js from 'asn1js';
import { derSerializeHomogeneousSequence } from '../../asn1';

import { MAX_SDU_PLAINTEXT_LENGTH } from '../../ramf/serialization';
import { CERTIFICATE_ROTATION_FORMAT_SIGNATURE, CertificateRotation } from '../CertificateRotation';
import InvalidMessageError from '../InvalidMessageError';
import Parcel from '../Parcel';
import { ParcelCollectionAck } from '../ParcelCollectionAck';
import PayloadPlaintext from './PayloadPlaintext';

/**
 * Number of octets needed to represent the type and length of an 8 MiB value in DER.
 */
const DER_TL_OVERHEAD_OCTETS = 5;

export interface MessageWithExpiryDate {
  readonly messageSerialized: ArrayBuffer;
  readonly expiryDate: Date;
}

export type CargoMessageSetItem = Parcel | ParcelCollectionAck | CertificateRotation;

/**
 * Plaintext representation of the payload in a cargo message.
 *
 * That is, the set of RAMF messages the cargo contains.
 */
export default class CargoMessageSet implements PayloadPlaintext {
  /**
   * Maximum number of octets for any serialized message to be included in a cargo.
   *
   * This is the result of subtracting the TLVs for the SET and OCTET STRING values from the
   * maximum size of an SDU to be encrypted.
   */
  public static readonly MAX_MESSAGE_LENGTH = MAX_SDU_PLAINTEXT_LENGTH - DER_TL_OVERHEAD_OCTETS * 2;

  public static deserialize(serialization: ArrayBuffer): CargoMessageSet {
    const result = asn1js.verifySchema(serialization, CargoMessageSet.ASN1_SCHEMA);
    if (!result.verified) {
      throw new InvalidMessageError('Serialization is not a valid CargoMessageSet');
    }
    const messageSet: readonly asn1js.BitString[] = (result.result as any).message_set || [];
    const messages = messageSet.map((v) => v.valueBlock.valueHex);
    return new CargoMessageSet(messages);
  }

  /**
   * Deserialize a value if it's a legal item in a cargo message set.
   *
   * @param itemSerialized The parcel or PCA to be deserialized
   * @throws InvalidMessageError If `itemSerialized` is not a legal item in a cargo message set
   */
  public static async deserializeItem(itemSerialized: ArrayBuffer): Promise<CargoMessageSetItem> {
    const messageClass = getItemClass(itemSerialized);
    try {
      return await messageClass.deserialize(itemSerialized);
    } catch (error) {
      throw new InvalidMessageError(error as Error, 'Value is not a valid Cargo Message Set item');
    }
  }

  public static async *batchMessagesSerialized(
    messagesWithExpiryDate: AsyncIterable<MessageWithExpiryDate>,
  ): AsyncIterable<MessageWithExpiryDate> {
    // tslint:disable-next-line:readonly-array
    let currentBatch: ArrayBuffer[] = [];
    // tslint:disable-next-line:no-unnecessary-initializer
    let currentBatchExpiryDate: Date | undefined = undefined;
    let availableOctetsInCurrentBatch = MAX_SDU_PLAINTEXT_LENGTH - DER_TL_OVERHEAD_OCTETS;

    for await (const { messageSerialized, expiryDate } of messagesWithExpiryDate) {
      if (CargoMessageSet.MAX_MESSAGE_LENGTH < messageSerialized.byteLength) {
        throw new InvalidMessageError(
          `Cargo messages must not exceed ${CargoMessageSet.MAX_MESSAGE_LENGTH} octets ` +
            `(got one with ${messageSerialized.byteLength} octets)`,
        );
      }

      currentBatchExpiryDate = currentBatchExpiryDate ?? expiryDate;

      const messageTlvLength = DER_TL_OVERHEAD_OCTETS + messageSerialized.byteLength;
      const messageFitsInCurrentBatch = messageTlvLength <= availableOctetsInCurrentBatch;
      if (messageFitsInCurrentBatch) {
        currentBatch.push(messageSerialized);
        currentBatchExpiryDate =
          currentBatchExpiryDate < expiryDate ? expiryDate : currentBatchExpiryDate;
        availableOctetsInCurrentBatch -= messageTlvLength;
      } else {
        const cargoMessageSet = new CargoMessageSet(currentBatch);
        yield {
          expiryDate: currentBatchExpiryDate,
          messageSerialized: cargoMessageSet.serialize(),
        };

        currentBatch = [messageSerialized];
        currentBatchExpiryDate = expiryDate;
        availableOctetsInCurrentBatch = MAX_SDU_PLAINTEXT_LENGTH - messageTlvLength;
      }
    }

    if (currentBatch.length) {
      const cargoMessageSet = new CargoMessageSet(currentBatch);
      yield {
        expiryDate: currentBatchExpiryDate as Date,
        messageSerialized: cargoMessageSet.serialize(),
      };
    }
  }

  protected static readonly ASN1_SCHEMA = new asn1js.Sequence({
    name: 'CargoMessages',
    // @ts-ignore
    value: [
      new asn1js.Repeated({
        name: 'message_set',
        // @ts-ignore
        value: new asn1js.OctetString({ name: 'message' }),
      }),
    ],
  });

  constructor(public readonly messages: readonly ArrayBuffer[]) {}

  public serialize(): ArrayBuffer {
    const messagesSerialized = Array.from(this.messages).map(
      (m) => new asn1js.OctetString({ valueHex: m }),
    );
    return derSerializeHomogeneousSequence(messagesSerialized);
  }
}

function getItemClass(itemSerialized: ArrayBuffer): {
  readonly deserialize: (s: ArrayBuffer) => CargoMessageSetItem | Promise<CargoMessageSetItem>;
} {
  const messageFormatSignature = Buffer.from(itemSerialized.slice(0, 10));

  if (messageFormatSignature.equals(ParcelCollectionAck.FORMAT_SIGNATURE)) {
    return ParcelCollectionAck;
  }
  if (messageFormatSignature.equals(CERTIFICATE_ROTATION_FORMAT_SIGNATURE)) {
    return CertificateRotation;
  }

  return Parcel;
}
