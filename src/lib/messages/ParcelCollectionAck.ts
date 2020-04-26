import * as asn1js from 'asn1js';

import { generateFormatSignature } from './formatSignature';
import InvalidMessageError from './InvalidMessageError';

export interface ParcelCollectionAck {
  readonly senderEndpointPrivateAddress: string;
  readonly recipientEndpointAddress: string;
  readonly parcelId: string;
}

export class ParcelCollectionAckSet {
  public static readonly FORMAT_SIGNATURE = generateFormatSignature(0x51, 0);

  public static deserialize(pcaSerialized: ArrayBuffer): ParcelCollectionAckSet {
    const formatSignature = Buffer.from(
      pcaSerialized.slice(0, ParcelCollectionAckSet.FORMAT_SIGNATURE.byteLength),
    );
    if (!formatSignature.equals(ParcelCollectionAckSet.FORMAT_SIGNATURE)) {
      throw new InvalidMessageError('Format signature should be that of a PCA set');
    }

    const pcaSetSerialized = pcaSerialized.slice(10);
    const result = asn1js.verifySchema(pcaSetSerialized, ParcelCollectionAckSet.SCHEMA);
    if (!result.verified) {
      throw new InvalidMessageError('PCA set did not meet required structure');
    }

    const ackBlocks: readonly asn1js.Set[] = (result.result as any).ack_set ?? [];
    const acks: readonly ParcelCollectionAck[] = ackBlocks.map(ackBlock => ({
      parcelId: (ackBlock.valueBlock.value[2] as asn1js.VisibleString).valueBlock.value,
      recipientEndpointAddress: (ackBlock.valueBlock.value[1] as asn1js.VisibleString).valueBlock
        .value,
      senderEndpointPrivateAddress: (ackBlock.valueBlock.value[0] as asn1js.VisibleString)
        .valueBlock.value,
    }));
    return new ParcelCollectionAckSet(new Set(acks));
  }

  private static readonly SCHEMA = new asn1js.Set({
    name: 'ParcelCollectionAckSet',
    value: [
      new asn1js.Repeated({
        name: 'ack_set',
        value: new asn1js.Sequence({
          name: 'ack',
          value: [
            new asn1js.VisibleString({
              name: 'senderEndpointPrivateAddress',
              optional: false,
            } as any),
            new asn1js.VisibleString({ name: 'recipientEndpointAddress', optional: false } as any),
            new asn1js.VisibleString({ name: 'parcelId', optional: false } as any),
          ],
        } as any),
      } as any),
    ],
  } as any);

  constructor(public readonly ackSet: ReadonlySet<ParcelCollectionAck>) {}

  public serialize(): ArrayBuffer {
    const ackSequences = [...this.ackSet].map(
      ack =>
        new asn1js.Sequence({
          value: [
            new asn1js.VisibleString({ value: ack.senderEndpointPrivateAddress }),
            new asn1js.VisibleString({ value: ack.recipientEndpointAddress }),
            new asn1js.VisibleString({ value: ack.parcelId }),
          ],
        } as any),
    );
    const ackSetSerialized = new asn1js.Set({ value: ackSequences } as any).toBER(false);
    const serialization = new ArrayBuffer(
      ParcelCollectionAckSet.FORMAT_SIGNATURE.byteLength + ackSetSerialized.byteLength,
    );
    const serializationView = new Uint8Array(serialization);
    serializationView.set(ParcelCollectionAckSet.FORMAT_SIGNATURE, 0);
    serializationView.set(
      new Uint8Array(ackSetSerialized),
      ParcelCollectionAckSet.FORMAT_SIGNATURE.byteLength,
    );
    return serialization;
  }
}
