import { Primitive, verifySchema, VisibleString } from 'asn1js';
import { TextDecoder } from 'util';
import { makeHeterogeneousSequenceSchema, makeImplicitlyTaggedSequence } from '../asn1';
import { generateFormatSignature } from './formatSignature';
import InvalidMessageError from './InvalidMessageError';
export class ParcelCollectionAck {
    senderEndpointPrivateAddress;
    recipientEndpointAddress;
    parcelId;
    static FORMAT_SIGNATURE = generateFormatSignature(0x51, 0);
    static deserialize(pcaSerialized) {
        const formatSignature = Buffer.from(pcaSerialized.slice(0, ParcelCollectionAck.FORMAT_SIGNATURE.byteLength));
        if (!formatSignature.equals(ParcelCollectionAck.FORMAT_SIGNATURE)) {
            throw new InvalidMessageError('Format signature should be that of a PCA');
        }
        const pcaSequenceSerialized = pcaSerialized.slice(10);
        const result = verifySchema(pcaSequenceSerialized, ParcelCollectionAck.SCHEMA);
        if (!result.verified) {
            throw new InvalidMessageError('PCA did not meet required structure');
        }
        const textDecoder = new TextDecoder();
        const pcaBlock = result.result.ParcelCollectionAck;
        return new ParcelCollectionAck(textDecoder.decode(pcaBlock.senderEndpointPrivateAddress.valueBlock.valueHex), textDecoder.decode(pcaBlock.recipientEndpointAddress.valueBlock.valueHex), textDecoder.decode(pcaBlock.parcelId.valueBlock.valueHex));
    }
    static SCHEMA = makeHeterogeneousSequenceSchema('ParcelCollectionAck', [
        new Primitive({ name: 'senderEndpointPrivateAddress' }),
        new Primitive({ name: 'recipientEndpointAddress' }),
        new Primitive({ name: 'parcelId' }),
    ]);
    constructor(senderEndpointPrivateAddress, recipientEndpointAddress, parcelId) {
        this.senderEndpointPrivateAddress = senderEndpointPrivateAddress;
        this.recipientEndpointAddress = recipientEndpointAddress;
        this.parcelId = parcelId;
    }
    serialize() {
        const ackSerialized = makeImplicitlyTaggedSequence(new VisibleString({ value: this.senderEndpointPrivateAddress }), new VisibleString({ value: this.recipientEndpointAddress }), new VisibleString({ value: this.parcelId })).toBER();
        const serialization = new ArrayBuffer(ParcelCollectionAck.FORMAT_SIGNATURE.byteLength + ackSerialized.byteLength);
        const serializationView = new Uint8Array(serialization);
        serializationView.set(ParcelCollectionAck.FORMAT_SIGNATURE, 0);
        serializationView.set(new Uint8Array(ackSerialized), ParcelCollectionAck.FORMAT_SIGNATURE.byteLength);
        return serialization;
    }
}
//# sourceMappingURL=ParcelCollectionAck.js.map