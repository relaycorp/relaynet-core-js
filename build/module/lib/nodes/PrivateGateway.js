import { PrivateNodeRegistrationRequest } from '../bindings/gsc/PrivateNodeRegistrationRequest';
import { CertificationPath } from '../pki/CertificationPath';
import { PrivatePublicGatewayChannel } from './channels/PrivatePublicGatewayChannel';
import { NodeError } from './errors';
import { Gateway } from './Gateway';
export class PrivateGateway extends Gateway {
    /**
     * Produce a `PrivateNodeRegistrationRequest` to register with a public gateway.
     *
     * @param authorizationSerialized
     */
    async requestPublicGatewayRegistration(authorizationSerialized) {
        const request = new PrivateNodeRegistrationRequest(await this.getIdentityPublicKey(), authorizationSerialized);
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
            throw new NodeError('Delivery authorization was not issued by public gateway');
        }
        const publicGatewayPrivateAddress = deliveryAuthorization.getIssuerPrivateAddress();
        await this.keyStores.certificateStore.save(new CertificationPath(deliveryAuthorization, []), publicGatewayPrivateAddress);
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
        return new PrivatePublicGatewayChannel(this.identityPrivateKey, privateGatewayDeliveryAuth.leafCertificate, publicGatewayPrivateAddress, publicGatewayPublicKey, publicGatewayPublicAddress, this.keyStores, this.cryptoOptions);
    }
}
//# sourceMappingURL=PrivateGateway.js.map