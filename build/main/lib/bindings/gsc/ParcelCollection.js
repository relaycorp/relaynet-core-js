"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ParcelCollection = void 0;
const Parcel_1 = __importDefault(require("../../messages/Parcel"));
const RecipientAddressType_1 = require("../../messages/RecipientAddressType");
class ParcelCollection {
    constructor(parcelSerialized, trustedCertificates, ackCallback) {
        this.parcelSerialized = parcelSerialized;
        this.trustedCertificates = trustedCertificates;
        this.ackCallback = ackCallback;
    }
    async ack() {
        await this.ackCallback();
    }
    async deserializeAndValidateParcel() {
        const parcel = await Parcel_1.default.deserialize(this.parcelSerialized);
        await parcel.validate(RecipientAddressType_1.RecipientAddressType.PRIVATE, this.trustedCertificates);
        return parcel;
    }
}
exports.ParcelCollection = ParcelCollection;
//# sourceMappingURL=ParcelCollection.js.map