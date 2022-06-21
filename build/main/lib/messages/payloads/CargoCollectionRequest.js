"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.CargoCollectionRequest = void 0;
const asn1js_1 = require("asn1js");
const asn1_1 = require("../../asn1");
const Certificate_1 = __importDefault(require("../../crypto_wrappers/x509/Certificate"));
const InvalidMessageError_1 = __importDefault(require("../InvalidMessageError"));
class CargoCollectionRequest {
    constructor(cargoDeliveryAuthorization) {
        this.cargoDeliveryAuthorization = cargoDeliveryAuthorization;
    }
    static deserialize(serialization) {
        const result = (0, asn1js_1.verifySchema)(serialization, CargoCollectionRequest.SCHEMA);
        if (!result.verified) {
            throw new InvalidMessageError_1.default('Serialization is not a valid CargoCollectionRequest');
        }
        const requestASN1 = result.result.CargoCollectionRequest;
        const cdaSerialized = requestASN1.cda.valueBlock.valueHex;
        let cda;
        try {
            cda = Certificate_1.default.deserialize(cdaSerialized);
        }
        catch (error) {
            throw new InvalidMessageError_1.default(error, 'CargoCollectionRequest contains a malformed Cargo Delivery Authorization');
        }
        return new CargoCollectionRequest(cda);
    }
    serialize() {
        const cdaASN1 = new asn1js_1.OctetString({ valueHex: this.cargoDeliveryAuthorization.serialize() });
        return (0, asn1_1.makeImplicitlyTaggedSequence)(cdaASN1).toBER();
    }
}
exports.CargoCollectionRequest = CargoCollectionRequest;
CargoCollectionRequest.SCHEMA = (0, asn1_1.makeHeterogeneousSequenceSchema)('CargoCollectionRequest', [
    new asn1js_1.Primitive({ name: 'cda' }),
]);
//# sourceMappingURL=CargoCollectionRequest.js.map