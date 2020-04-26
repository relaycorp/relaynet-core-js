import * as asn1js from 'asn1js';

import { generateFormatSignature } from './formatSignature';

export interface ParcelCollectionAcknowledgement {
  readonly senderEndpointPrivateAddress: string;
  readonly recipientEndpointAddress: string;
  readonly parcelId: string;
}

export class ParcelCollectionAcknowledgementSet {
  public static readonly FORMAT_SIGNATURE = generateFormatSignature(0x51, 0);

  public static deserialize(_pcaSerialized: ArrayBuffer): ParcelCollectionAcknowledgementSet {
    throw new Error('Implement!');
  }

  constructor(public readonly acks: ReadonlySet<ParcelCollectionAcknowledgement>) {}

  public serialize(): ArrayBuffer {
    const ackSequences = [...this.acks].map(
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
      ParcelCollectionAcknowledgementSet.FORMAT_SIGNATURE.byteLength + ackSetSerialized.byteLength,
    );
    const serializationView = new Uint8Array(serialization);
    serializationView.set(ParcelCollectionAcknowledgementSet.FORMAT_SIGNATURE, 0);
    serializationView.set(
      new Uint8Array(ackSetSerialized),
      ParcelCollectionAcknowledgementSet.FORMAT_SIGNATURE.byteLength,
    );
    return serialization;
  }
}
