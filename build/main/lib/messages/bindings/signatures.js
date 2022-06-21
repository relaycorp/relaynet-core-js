"use strict";
// tslint:disable:max-classes-per-file
Object.defineProperty(exports, "__esModule", { value: true });
exports.ParcelDeliveryVerifier = exports.ParcelCollectionHandshakeVerifier = exports.ParcelDeliverySigner = exports.ParcelCollectionHandshakeSigner = void 0;
const Signer_1 = require("../../nodes/signatures/Signer");
const Verifier_1 = require("../../nodes/signatures/Verifier");
const oids_1 = require("../../oids");
class ParcelCollectionHandshakeSigner extends Signer_1.Signer {
    constructor() {
        super(...arguments);
        this.oid = oids_1.RELAYNET_OIDS.SIGNATURE.PARCEL_COLLECTION_HANDSHAKE;
    }
}
exports.ParcelCollectionHandshakeSigner = ParcelCollectionHandshakeSigner;
class ParcelDeliverySigner extends Signer_1.Signer {
    constructor() {
        super(...arguments);
        this.oid = oids_1.RELAYNET_OIDS.SIGNATURE.PARCEL_DELIVERY;
    }
}
exports.ParcelDeliverySigner = ParcelDeliverySigner;
class ParcelCollectionHandshakeVerifier extends Verifier_1.Verifier {
    constructor() {
        super(...arguments);
        this.oid = oids_1.RELAYNET_OIDS.SIGNATURE.PARCEL_COLLECTION_HANDSHAKE;
    }
}
exports.ParcelCollectionHandshakeVerifier = ParcelCollectionHandshakeVerifier;
class ParcelDeliveryVerifier extends Verifier_1.Verifier {
    constructor() {
        super(...arguments);
        this.oid = oids_1.RELAYNET_OIDS.SIGNATURE.PARCEL_DELIVERY;
    }
}
exports.ParcelDeliveryVerifier = ParcelDeliveryVerifier;
//# sourceMappingURL=signatures.js.map