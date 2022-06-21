"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PrivatePublicGatewayChannel = void 0;
const date_fns_1 = require("date-fns");
const PrivateNodeRegistration_1 = require("../../bindings/gsc/PrivateNodeRegistration");
const PrivateNodeRegistrationAuthorization_1 = require("../../bindings/gsc/PrivateNodeRegistrationAuthorization");
const keys_1 = require("../../crypto_wrappers/keys");
const CargoCollectionAuthorization_1 = require("../../messages/CargoCollectionAuthorization");
const CargoCollectionRequest_1 = require("../../messages/payloads/CargoCollectionRequest");
const issuance_1 = require("../../pki/issuance");
const PrivateGatewayChannel_1 = require("./PrivateGatewayChannel");
const CLOCK_DRIFT_TOLERANCE_MINUTES = 90;
const OUTBOUND_CARGO_TTL_DAYS = 14;
/**
 * Channel between a private gateway (the node) and its public gateway (the peer).
 */
class PrivatePublicGatewayChannel extends PrivateGatewayChannel_1.PrivateGatewayChannel {
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
        const authorization = new PrivateNodeRegistrationAuthorization_1.PrivateNodeRegistrationAuthorization(expiryDate, gatewayData);
        return authorization.serialize(this.nodePrivateKey);
    }
    /**
     * Parse `PrivateNodeRegistrationAuthorization` and return its `gatewayData` if valid.
     *
     * @param authorizationSerialized
     * @throws InvalidMessageError if the authorization is malformed, invalid or expired
     */
    async verifyEndpointRegistrationAuthorization(authorizationSerialized) {
        const publicKey = await (0, keys_1.getRSAPublicKeyFromPrivate)(this.nodePrivateKey);
        const authorization = await PrivateNodeRegistrationAuthorization_1.PrivateNodeRegistrationAuthorization.deserialize(authorizationSerialized, publicKey);
        return authorization.gatewayData;
    }
    /**
     * Return a `PrivateNodeRegistration` including a new certificate for `endpointPublicKey`.
     *
     * @param endpointPublicKey
     * @return The serialization of the registration
     */
    async registerEndpoint(endpointPublicKey) {
        const endpointCertificate = await (0, issuance_1.issueEndpointCertificate)({
            issuerCertificate: this.nodeDeliveryAuth,
            issuerPrivateKey: this.nodePrivateKey,
            subjectPublicKey: endpointPublicKey,
            validityEndDate: (0, date_fns_1.addMonths)(new Date(), 6),
        });
        const registration = new PrivateNodeRegistration_1.PrivateNodeRegistration(endpointCertificate, this.nodeDeliveryAuth);
        return registration.serialize();
    }
    //endregion
    async generateCCA() {
        const now = new Date();
        const startDate = (0, date_fns_1.subMinutes)(now, CLOCK_DRIFT_TOLERANCE_MINUTES);
        const endDate = (0, date_fns_1.addDays)(now, OUTBOUND_CARGO_TTL_DAYS);
        const cdaIssuer = await this.getOrCreateCDAIssuer();
        const cargoDeliveryAuthorization = await (0, issuance_1.issueGatewayCertificate)({
            issuerCertificate: cdaIssuer,
            issuerPrivateKey: this.nodePrivateKey,
            subjectPublicKey: this.peerPublicKey,
            validityEndDate: endDate,
        });
        const ccr = new CargoCollectionRequest_1.CargoCollectionRequest(cargoDeliveryAuthorization);
        const ccaPayload = await this.wrapMessagePayload(ccr);
        const cca = new CargoCollectionAuthorization_1.CargoCollectionAuthorization(this.getOutboundRAMFAddress(), this.nodeDeliveryAuth, Buffer.from(ccaPayload), { creationDate: startDate, ttl: (0, date_fns_1.differenceInSeconds)(endDate, startDate) });
        return cca.serialize(this.nodePrivateKey);
    }
}
exports.PrivatePublicGatewayChannel = PrivatePublicGatewayChannel;
//# sourceMappingURL=PrivatePublicGatewayChannel.js.map