"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.makeSafePlaintext = void 0;
const asn1js_1 = require("asn1js");
const asn1_1 = require("../../asn1");
function makeSafePlaintext(plaintext, oid) {
    return (0, asn1_1.makeImplicitlyTaggedSequence)(new asn1js_1.ObjectIdentifier({ value: oid }), new asn1js_1.OctetString({ valueHex: plaintext })).toBER();
}
exports.makeSafePlaintext = makeSafePlaintext;
//# sourceMappingURL=utils.js.map