import { Primitive, verifySchema, VisibleString } from 'asn1js';
import { TextDecoder } from 'util';

import { makeHeterogeneousSequenceSchema, makeImplicitlyTaggedSequence } from '../asn1';
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

    const pcaSequenceSerialized = pcaSerialized.slice(7);
    const result = verifySchema(pcaSequenceSerialized, ParcelCollectionAck.SCHEMA);
    if (!result.verified) {
      throw new InvalidMessageError('PCA did not meet required structure');
    }

    const textDecoder = new TextDecoder();
    const pcaBlock: any = (result.result as any).ParcelCollectionAck;
    return new ParcelCollectionAck(
      textDecoder.decode(pcaBlock.senderEndpointId.valueBlock.valueHex),
      textDecoder.decode(pcaBlock.recipientEndpointId.valueBlock.valueHex),
      textDecoder.decode(pcaBlock.parcelId.valueBlock.valueHex),
    );
  }

  private static readonly SCHEMA = makeHeterogeneousSequenceSchema('ParcelCollectionAck', [
    new Primitive({ name: 'senderEndpointId' }),
    new Primitive({ name: 'recipientEndpointId' }),
    new Primitive({ name: 'parcelId' }),
  ]);

  constructor(
    public readonly senderEndpointId: string,
    public readonly recipientEndpointId: string,
    public readonly parcelId: string,
  ) {}

  public serialize(): ArrayBuffer {
    const ackSerialized = makeImplicitlyTaggedSequence(
      new VisibleString({ value: this.senderEndpointId }),
      new VisibleString({ value: this.recipientEndpointId }),
      new VisibleString({ value: this.parcelId }),
    ).toBER();
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
