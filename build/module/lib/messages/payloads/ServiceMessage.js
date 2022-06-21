import { OctetString, Primitive, verifySchema, VisibleString } from 'asn1js';
import bufferToArray from 'buffer-to-arraybuffer';
import { TextDecoder } from 'util';
import { makeHeterogeneousSequenceSchema, makeImplicitlyTaggedSequence } from '../../asn1';
import InvalidMessageError from '../InvalidMessageError';
/**
 * Service message as encapsulated in a parcel.
 */
export default class ServiceMessage {
    type;
    content;
    /**
     * Initialize a service message from the `serialization`.
     *
     * @param serialization
     */
    static deserialize(serialization) {
        const result = verifySchema(serialization, ServiceMessage.SCHEMA);
        if (!result.verified) {
            throw new InvalidMessageError('Invalid service message serialization');
        }
        const messageASN1 = result.result.ServiceMessage;
        const type = new TextDecoder().decode(messageASN1.type.valueBlock.valueHex);
        const content = Buffer.from(messageASN1.content.valueBlock.valueHex);
        return new ServiceMessage(type, content);
    }
    static SCHEMA = makeHeterogeneousSequenceSchema('ServiceMessage', [
        new Primitive({ name: 'type' }),
        new Primitive({ name: 'content' }),
    ]);
    constructor(type, content) {
        this.type = type;
        this.content = content;
    }
    /**
     * Serialize service message.
     */
    serialize() {
        const typeASN1 = new VisibleString({ value: this.type });
        const contentASN1 = new OctetString({ valueHex: bufferToArray(this.content) });
        return makeImplicitlyTaggedSequence(typeASN1, contentASN1).toBER();
    }
}
//# sourceMappingURL=ServiceMessage.js.map