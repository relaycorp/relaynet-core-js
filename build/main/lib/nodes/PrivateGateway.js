"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PrivateGateway = void 0;
const PrivateNodeRegistrationRequest_1 = require("../bindings/gsc/PrivateNodeRegistrationRequest");
const CertificationPath_1 = require("../pki/CertificationPath");
const PrivatePublicGatewayChannel_1 = require("./channels/PrivatePublicGatewayChannel");
const errors_1 = require("./errors");
const Gateway_1 = require("./Gateway");
class PrivateGateway extends Gateway_1.Gateway {
    /**
     * Produce a `PrivateNodeRegistrationRequest` to register with a public gateway.
     *
     * @param authorizationSerialized
     */
    async requestPublicGatewayRegistration(authorizationSerialized) {
        const request = new PrivateNodeRegistrationRequest_1.PrivateNodeRegistrationRequest(await this.getIdentityPublicKey(), authorizationSerialized);
        return request.serialize(this.identityPrivateKey);
    }
    /**
     * Create channel with public gateway using registration details.
     *
     * @param deliveryAuthorization
     * @param publicGatewayIdentityCertificate
     * @param publicGatewaySessionPublicKey
     * @throws NodeError if the `publicGatewayIdentityCertificate` didn't issue
     *    `deliveryAuthorization`
     */
    async savePublicGatewayChannel(deliveryAuthorization, publicGatewayIdentityCertificate, publicGatewaySessionPublicKey) {
        try {
            await deliveryAuthorization.getCertificationPath([], [publicGatewayIdentityCertificate]);
        }
        catch (_) {
            throw new errors_1.NodeError('Delivery authorization was not issued by public gateway');
        }
        const publicGatewayPrivateAddress = deliveryAuthorization.getIssuerPrivateAddress();
        await this.keyStores.certificateStore.save(new CertificationPath_1.CertificationPath(deliveryAuthorization, []), publicGatewayPrivateAddress);
        await this.keyStores.publicKeyStore.saveIdentityKey(await publicGatewayIdentityCertificate.getPublicKey());
        await this.keyStores.publicKeyStore.saveSessionKey(publicGatewaySessionPublicKey, publicGatewayPrivateAddress, new Date());
    }
    async retrievePublicGatewayChannel(publicGatewayPrivateAddress, publicGatewayPublicAddress) {
        const publicGatewayPublicKey = await this.keyStores.publicKeyStore.retrieveIdentityKey(publicGatewayPrivateAddress);
        if (!publicGatewayPublicKey) {
            return null;
        }
        const privateGatewayDeliveryAuth = await this.keyStores.certificateStore.retrieveLatest(this.privateAddress, publicGatewayPrivateAddress);
        if (!privateGatewayDeliveryAuth) {
            return null;
        }
        return new PrivatePublicGatewayChannel_1.PrivatePublicGatewayChannel(this.identityPrivateKey, privateGatewayDeliveryAuth.leafCertificate, publicGatewayPrivateAddress, publicGatewayPublicKey, publicGatewayPublicAddress, this.keyStores, this.cryptoOptions);
    }
}
exports.PrivateGateway = PrivateGateway;
//# sourceMappingURL=PrivateGateway.js.map