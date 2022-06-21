"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PrivateGatewayChannel = void 0;
const date_fns_1 = require("date-fns");
const keys_1 = require("../../crypto_wrappers/keys");
const CertificationPath_1 = require("../../pki/CertificationPath");
const issuance_1 = require("../../pki/issuance");
const GatewayChannel_1 = require("./GatewayChannel");
/**
 * Channel whose node is a private gateway.
 */
class PrivateGatewayChannel extends GatewayChannel_1.GatewayChannel {
    async getOrCreateCDAIssuer() {
        const now = new Date();
        const publicKey = await (0, keys_1.getRSAPublicKeyFromPrivate)(this.nodePrivateKey);
        const privateAddress = await (0, keys_1.getPrivateAddressFromIdentityKey)(publicKey);
        const existingIssuerPath = await this.keyStores.certificateStore.retrieveLatest(privateAddress, privateAddress);
        if (existingIssuerPath) {
            const minExpiryDate = (0, date_fns_1.addDays)(now, 90);
            if (minExpiryDate <= existingIssuerPath.leafCertificate.expiryDate) {
                return existingIssuerPath.leafCertificate;
            }
        }
        const issuer = await (0, issuance_1.issueGatewayCertificate)({
            issuerPrivateKey: this.nodePrivateKey,
            subjectPublicKey: publicKey,
            validityEndDate: (0, date_fns_1.addDays)(now, 180),
            validityStartDate: (0, date_fns_1.subMinutes)(now, 90),
        });
        const path = new CertificationPath_1.CertificationPath(issuer, []);
        await this.keyStores.certificateStore.save(path, privateAddress);
        return issuer;
    }
    /**
     * Get all CDA issuers in the channel.
     */
    async getCDAIssuers() {
        const publicKey = await (0, keys_1.getRSAPublicKeyFromPrivate)(this.nodePrivateKey);
        const privateAddress = await (0, keys_1.getPrivateAddressFromIdentityKey)(publicKey);
        const issuerPaths = await this.keyStores.certificateStore.retrieveAll(privateAddress, privateAddress);
        return issuerPaths.map((p) => p.leafCertificate);
    }
}
exports.PrivateGatewayChannel = PrivateGatewayChannel;
//# sourceMappingURL=PrivateGatewayChannel.js.map