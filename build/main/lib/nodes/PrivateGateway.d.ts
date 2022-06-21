import Certificate from '../crypto_wrappers/x509/Certificate';
import { SessionKey } from '../SessionKey';
import { PrivatePublicGatewayChannel } from './channels/PrivatePublicGatewayChannel';
import { Gateway } from './Gateway';
export declare class PrivateGateway extends Gateway {
    /**
     * Produce a `PrivateNodeRegistrationRequest` to register with a public gateway.
     *
     * @param authorizationSerialized
     */
    requestPublicGatewayRegistration(authorizationSerialized: ArrayBuffer): Promise<ArrayBuffer>;
    /**
     * Create channel with public gateway using registration details.
     *
     * @param deliveryAuthorization
     * @param publicGatewayIdentityCertificate
     * @param publicGatewaySessionPublicKey
     * @throws NodeError if the `publicGatewayIdentityCertificate` didn't issue
     *    `deliveryAuthorization`
     */
    savePublicGatewayChannel(deliveryAuthorization: Certificate, publicGatewayIdentityCertificate: Certificate, publicGatewaySessionPublicKey: SessionKey): Promise<void>;
    retrievePublicGatewayChannel(publicGatewayPrivateAddress: string, publicGatewayPublicAddress: string): Promise<PrivatePublicGatewayChannel | null>;
}
