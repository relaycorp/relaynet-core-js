"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const asn1js_1 = require("asn1js");
const buffer_to_arraybuffer_1 = __importDefault(require("buffer-to-arraybuffer"));
const util_1 = require("util");
const asn1_1 = require("../../asn1");
const InvalidMessageError_1 = __importDefault(require("../InvalidMessageError"));
/**
 * Service message as encapsulated in a parcel.
 */
class ServiceMessage {
    constructor(type, content) {
        this.type = type;
        this.content = content;
    }
    /**
     * Initialize a service message from the `serialization`.
     *
     * @param serialization
     */
    static deserialize(serialization) {
        const result = (0, asn1js_1.verifySchema)(serialization, ServiceMessage.SCHEMA);
        if (!result.verified) {
            throw new InvalidMessageError_1.default('Invalid service message serialization');
        }
        const messageASN1 = result.result.ServiceMessage;
        const type = new util_1.TextDecoder().decode(messageASN1.type.valueBlock.valueHex);
        const content = Buffer.from(messageASN1.content.valueBlock.valueHex);
        return new ServiceMessage(type, content);
    }
    /**
     * Serialize service message.
     */
    serialize() {
        const typeASN1 = new asn1js_1.VisibleString({ value: this.type });
        const contentASN1 = new asn1js_1.OctetString({ valueHex: (0, buffer_to_arraybuffer_1.default)(this.content) });
        return (0, asn1_1.makeImplicitlyTaggedSequence)(typeASN1, contentASN1).toBER();
    }
}
exports.default = ServiceMessage;
ServiceMessage.SCHEMA = (0, asn1_1.makeHeterogeneousSequenceSchema)('ServiceMessage', [
    new asn1js_1.Primitive({ name: 'type' }),
    new asn1js_1.Primitive({ name: 'content' }),
]);
//# sourceMappingURL=ServiceMessage.js.map