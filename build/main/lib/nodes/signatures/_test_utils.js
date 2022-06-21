"use strict";
// tslint:disable:max-classes-per-file
Object.defineProperty(exports, "__esModule", { value: true });
exports.StubVerifier = exports.StubSigner = exports.STUB_OID_VALUE = void 0;
const Signer_1 = require("./Signer");
const Verifier_1 = require("./Verifier");
exports.STUB_OID_VALUE = '1.2.3.4';
class StubSigner extends Signer_1.Signer {
    constructor() {
        super(...arguments);
        this.oid = exports.STUB_OID_VALUE;
    }
}
exports.StubSigner = StubSigner;
class StubVerifier extends Verifier_1.Verifier {
    constructor() {
        super(...arguments);
        this.oid = exports.STUB_OID_VALUE;
    }
    getTrustedCertificates() {
        return this.trustedCertificates;
    }
}
exports.StubVerifier = StubVerifier;
//# sourceMappingURL=_test_utils.js.map