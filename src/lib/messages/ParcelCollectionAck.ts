import * as asn1js from 'asn1js';

import { generateFormatSignature } from './formatSignature';
import InvalidMessageError from './InvalidMessageError';

export class ParcelCollectionAck {
  public static readonly FORMAT_SIGNATURE = generateFormatSignature(0x51, 0);

  public static deserialize(pcaSerialized: ArrayBuffer): ParcelCollectionAck {
    const formatSignature = Buffer.from(
      pcaSerialized.slice(0, ParcelCollectionAck.FORMAT_SIGNATURE.byteLength),
    );
    if (!formatSignature.equals(ParcelCollectionAck.FORMAT_SIGNATURE)) {
      throw new InvalidMessageError('Format signature should be that of a PCA');
    }

    const pcaSequenceSerialized = pcaSerialized.slice(10);
    const result = asn1js.verifySchema(pcaSequenceSerialized, ParcelCollectionAck.SCHEMA);
    if (!result.verified) {
      throw new InvalidMessageError('PCA did not meet required structure');
    }

    const pcaBlock: any = (result.result as any).ParcelCollectionAck;
    return new ParcelCollectionAck(
      (pcaBlock.senderEndpointPrivateAddress as asn1js.VisibleString).valueBlock.value,
      (pcaBlock.recipientEndpointAddress as asn1js.VisibleString).valueBlock.value,
      (pcaBlock.parcelId as asn1js.VisibleString).valueBlock.value,
    );
  }

  private static readonly SCHEMA = new asn1js.Sequence({
    name: 'ParcelCollectionAck',
    value: [
      new asn1js.VisibleString({ name: 'senderEndpointPrivateAddress', optional: false } as any),
      new asn1js.VisibleString({ name: 'recipientEndpointAddress', optional: false } as any),
      new asn1js.VisibleString({ name: 'parcelId', optional: false } as any),
    ],
  } as any);

  constructor(
    public readonly senderEndpointPrivateAddress: string,
    public readonly recipientEndpointAddress: string,
    public readonly parcelId: string,
  ) {}

  public serialize(): ArrayBuffer {
    const ackBlock = new asn1js.Sequence({
      value: [
        new asn1js.VisibleString({ value: this.senderEndpointPrivateAddress }),
        new asn1js.VisibleString({ value: this.recipientEndpointAddress }),
        new asn1js.VisibleString({ value: this.parcelId }),
      ],
    } as any);
    const ackSerialized = ackBlock.toBER(false);
    const serialization = new ArrayBuffer(
      ParcelCollectionAck.FORMAT_SIGNATURE.byteLength + ackSerialized.byteLength,
    );
    const serializationView = new Uint8Array(serialization);
    serializationView.set(ParcelCollectionAck.FORMAT_SIGNATURE, 0);
    serializationView.set(
      new Uint8Array(ackSerialized),
      ParcelCollectionAck.FORMAT_SIGNATURE.byteLength,
    );
    return serialization;
  }
}
