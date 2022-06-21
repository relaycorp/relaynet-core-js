"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const asn1js_1 = require("asn1js");
const _test_utils_1 = require("../../_test_utils");
const asn1_1 = require("../../asn1");
const _utils_1 = require("../../crypto_wrappers/_utils");
const InvalidMessageError_1 = __importDefault(require("../InvalidMessageError"));
const CargoCollectionRequest_1 = require("./CargoCollectionRequest");
let cargoDeliveryAuthorization;
beforeAll(async () => {
    cargoDeliveryAuthorization = await (0, _test_utils_1.generateStubCert)();
});
describe('serialize', () => {
    test('Cargo Delivery Authorization should be included DER-encoded', () => {
        const request = new CargoCollectionRequest_1.CargoCollectionRequest(cargoDeliveryAuthorization);
        const serialization = request.serialize();
        const sequence = (0, _utils_1.derDeserialize)(serialization);
        const cdaSerialized = (0, _test_utils_1.getAsn1SequenceItem)(sequence, 0).valueBlock.valueHex;
        (0, _test_utils_1.expectArrayBuffersToEqual)(cargoDeliveryAuthorization.serialize(), cdaSerialized);
    });
});
describe('deserialize', () => {
    test('Malformed sequences should be refused', () => {
        expect(() => CargoCollectionRequest_1.CargoCollectionRequest.deserialize((0, _test_utils_1.arrayBufferFrom)('malformed'))).toThrowWithMessage(InvalidMessageError_1.default, 'Serialization is not a valid CargoCollectionRequest');
    });
    test('Sequence should have at least one item', () => {
        expect(() => CargoCollectionRequest_1.CargoCollectionRequest.deserialize((0, asn1_1.makeImplicitlyTaggedSequence)().toBER())).toThrowWithMessage(InvalidMessageError_1.default, 'Serialization is not a valid CargoCollectionRequest');
    });
    test('Malformed Cargo Delivery Authorizations should be refused', () => {
        const invalidCertificate = new asn1js_1.Integer({ value: 42 });
        expect(() => CargoCollectionRequest_1.CargoCollectionRequest.deserialize((0, asn1_1.makeImplicitlyTaggedSequence)(invalidCertificate).toBER())).toThrowWithMessage(InvalidMessageError_1.default, /^CargoCollectionRequest contains a malformed Cargo Delivery Authorization: /);
    });
    test('Valid values should be accepted', () => {
        const request = new CargoCollectionRequest_1.CargoCollectionRequest(cargoDeliveryAuthorization);
        const requestDeserialized = CargoCollectionRequest_1.CargoCollectionRequest.deserialize(request.serialize());
        expect(requestDeserialized.cargoDeliveryAuthorization.isEqual(cargoDeliveryAuthorization)).toBeTrue();
    });
});
//# sourceMappingURL=CargoCollectionRequest.spec.js.map