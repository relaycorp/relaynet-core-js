import { addDays, addMonths, differenceInSeconds, subMinutes } from 'date-fns';
import { PrivateNodeRegistration } from '../../bindings/gsc/PrivateNodeRegistration';
import { PrivateNodeRegistrationAuthorization } from '../../bindings/gsc/PrivateNodeRegistrationAuthorization';
import { getRSAPublicKeyFromPrivate } from '../../crypto_wrappers/keys';
import { CargoCollectionAuthorization } from '../../messages/CargoCollectionAuthorization';
import { CargoCollectionRequest } from '../../messages/payloads/CargoCollectionRequest';
import { issueEndpointCertificate, issueGatewayCertificate } from '../../pki/issuance';
import { PrivateGatewayChannel } from './PrivateGatewayChannel';
const CLOCK_DRIFT_TOLERANCE_MINUTES = 90;
const OUTBOUND_CARGO_TTL_DAYS = 14;
/**
 * Channel between a private gateway (the node) and its public gateway (the peer).
 */
export class PrivatePublicGatewayChannel extends PrivateGatewayChannel {
    publicGatewayPublicAddress;
    /**
     * @internal
     */
    constructor(privateGatewayPrivateKey, privateGatewayDeliveryAuth, publicGatewayPrivateAddress, publicGatewayPublicKey, publicGatewayPublicAddress, keyStores, cryptoOptions) {
        super(privateGatewayPrivateKey, privateGatewayDeliveryAuth, publicGatewayPrivateAddress, publicGatewayPublicKey, keyStores, cryptoOptions);
        this.publicGatewayPublicAddress = publicGatewayPublicAddress;
    }
    getOutboundRAMFAddress() {
        return `https://${this.publicGatewayPublicAddress}`;
    }
    //region Private endpoint registration
    /**
     * Generate a `PrivateNodeRegistrationAuthorization` with the `gatewayData` and `expiryDate`.
     *
     * @param gatewayData
     * @param expiryDate
     */
    async authorizeEndpointRegistration(gatewayData, expiryDate) {
        const authorization = new PrivateNodeRegistrationAuthorization(expiryDate, gatewayData);
        return authorization.serialize(this.nodePrivateKey);
    }
    /**
     * Parse `PrivateNodeRegistrationAuthorization` and return its `gatewayData` if valid.
     *
     * @param authorizationSerialized
     * @throws InvalidMessageError if the authorization is malformed, invalid or expired
     */
    async verifyEndpointRegistrationAuthorization(authorizationSerialized) {
        const publicKey = await getRSAPublicKeyFromPrivate(this.nodePrivateKey);
        const authorization = await PrivateNodeRegistrationAuthorization.deserialize(authorizationSerialized, publicKey);
        return authorization.gatewayData;
    }
    /**
     * Return a `PrivateNodeRegistration` including a new certificate for `endpointPublicKey`.
     *
     * @param endpointPublicKey
     * @return The serialization of the registration
     */
    async registerEndpoint(endpointPublicKey) {
        const endpointCertificate = await issueEndpointCertificate({
            issuerCertificate: this.nodeDeliveryAuth,
            issuerPrivateKey: this.nodePrivateKey,
            subjectPublicKey: endpointPublicKey,
            validityEndDate: addMonths(new Date(), 6),
        });
        const registration = new PrivateNodeRegistration(endpointCertificate, this.nodeDeliveryAuth);
        return registration.serialize();
    }
    //endregion
    async generateCCA() {
        const now = new Date();
        const startDate = subMinutes(now, CLOCK_DRIFT_TOLERANCE_MINUTES);
        const endDate = addDays(now, OUTBOUND_CARGO_TTL_DAYS);
        const cdaIssuer = await this.getOrCreateCDAIssuer();
        const cargoDeliveryAuthorization = await issueGatewayCertificate({
            issuerCertificate: cdaIssuer,
            issuerPrivateKey: this.nodePrivateKey,
            subjectPublicKey: this.peerPublicKey,
            validityEndDate: endDate,
        });
        const ccr = new CargoCollectionRequest(cargoDeliveryAuthorization);
        const ccaPayload = await this.wrapMessagePayload(ccr);
        const cca = new CargoCollectionAuthorization(this.getOutboundRAMFAddress(), this.nodeDeliveryAuth, Buffer.from(ccaPayload), { creationDate: startDate, ttl: differenceInSeconds(endDate, startDate) });
        return cca.serialize(this.nodePrivateKey);
    }
}
//# sourceMappingURL=PrivatePublicGatewayChannel.js.map