"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.GatewayChannel = void 0;
const buffer_to_arraybuffer_1 = __importDefault(require("buffer-to-arraybuffer"));
const Cargo_1 = __importDefault(require("../../messages/Cargo"));
const CargoMessageSet_1 = __importDefault(require("../../messages/payloads/CargoMessageSet"));
const serialization_1 = require("../../ramf/serialization");
const Channel_1 = require("./Channel");
const CLOCK_DRIFT_TOLERANCE_HOURS = 3;
/**
 * Channel whose node is a gateway.
 */
class GatewayChannel extends Channel_1.Channel {
    async *generateCargoes(messages) {
        const messagesAsArrayBuffers = convertBufferMessagesToArrayBuffer(messages);
        const cargoMessageSets = CargoMessageSet_1.default.batchMessagesSerialized(messagesAsArrayBuffers);
        const recipientAddress = this.getOutboundRAMFAddress();
        for await (const { messageSerialized, expiryDate } of cargoMessageSets) {
            const creationDate = getCargoCreationTime();
            const ttl = getSecondsBetweenDates(creationDate, expiryDate);
            const cargo = new Cargo_1.default(recipientAddress, this.nodeDeliveryAuth, await this.encryptPayload(messageSerialized), { creationDate, ttl: Math.min(ttl, serialization_1.RAMF_MAX_TTL) });
            const cargoSerialized = await cargo.serialize(this.nodePrivateKey, this.cryptoOptions.signature);
            yield Buffer.from(cargoSerialized);
        }
    }
    async encryptPayload(payloadPlaintext) {
        const ciphertext = await this.wrapMessagePayload(payloadPlaintext);
        return Buffer.from(ciphertext);
    }
}
exports.GatewayChannel = GatewayChannel;
function getCargoCreationTime() {
    const creationDate = new Date();
    creationDate.setMilliseconds(0);
    creationDate.setHours(creationDate.getHours() - CLOCK_DRIFT_TOLERANCE_HOURS);
    return creationDate;
}
async function* convertBufferMessagesToArrayBuffer(messages) {
    for await (const { message, expiryDate } of messages) {
        yield { expiryDate, messageSerialized: (0, buffer_to_arraybuffer_1.default)(message) };
    }
}
function getSecondsBetweenDates(date, expiryDate) {
    return Math.floor((expiryDate.getTime() - date.getTime()) / 1000);
}
//# sourceMappingURL=GatewayChannel.js.map