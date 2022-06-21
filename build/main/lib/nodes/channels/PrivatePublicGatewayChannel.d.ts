import { PrivateGatewayChannel } from './PrivateGatewayChannel';
/**
 * Channel between a private gateway (the node) and its public gateway (the peer).
 */
export declare class PrivatePublicGatewayChannel extends PrivateGatewayChannel {
    readonly publicGatewayPublicAddress: string;
    getOutboundRAMFAddress(): string;
    /**
     * Generate a `PrivateNodeRegistrationAuthorization` with the `gatewayData` and `expiryDate`.
     *
     * @param gatewayData
     * @param expiryDate
     */
    authorizeEndpointRegistration(gatewayData: ArrayBuffer, expiryDate: Date): Promise<ArrayBuffer>;
    /**
     * Parse `PrivateNodeRegistrationAuthorization` and return its `gatewayData` if valid.
     *
     * @param authorizationSerialized
     * @throws InvalidMessageError if the authorization is malformed, invalid or expired
     */
    verifyEndpointRegistrationAuthorization(authorizationSerialized: ArrayBuffer): Promise<ArrayBuffer>;
    /**
     * Return a `PrivateNodeRegistration` including a new certificate for `endpointPublicKey`.
     *
     * @param endpointPublicKey
     * @return The serialization of the registration
     */
    registerEndpoint(endpointPublicKey: CryptoKey): Promise<ArrayBuffer>;
    generateCCA(): Promise<ArrayBuffer>;
}
