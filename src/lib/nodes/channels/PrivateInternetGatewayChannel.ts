import { addDays, addMonths, differenceInSeconds, subMinutes } from 'date-fns';

import { PrivateNodeRegistration } from '../../bindings/gsc/PrivateNodeRegistration';
import { PrivateNodeRegistrationAuthorization } from '../../bindings/gsc/PrivateNodeRegistrationAuthorization';
import { CargoCollectionAuthorization } from '../../messages/CargoCollectionAuthorization';
import { CargoCollectionRequest } from '../../messages/payloads/CargoCollectionRequest';
import { issueEndpointCertificate, issueGatewayCertificate } from '../../pki/issuance';
import { PrivateGatewayChannel } from './PrivateGatewayChannel';

const CLOCK_DRIFT_TOLERANCE_MINUTES = 90;
const OUTBOUND_CARGO_TTL_DAYS = 14;

/**
 * Channel between a private gateway (the node) and its Internet gateway (the peer).
 */
export class PrivateInternetGatewayChannel extends PrivateGatewayChannel<string> {
  /**
   * Generate a `PrivateNodeRegistrationAuthorization` with the `gatewayData` and `expiryDate`.
   *
   * @param gatewayData
   * @param expiryDate
   */
  public async authorizeEndpointRegistration(
    gatewayData: ArrayBuffer,
    expiryDate: Date,
  ): Promise<ArrayBuffer> {
    const authorization = new PrivateNodeRegistrationAuthorization(expiryDate, gatewayData);
    return authorization.serialize(this.node.identityKeyPair.privateKey);
  }

  /**
   * Parse `PrivateNodeRegistrationAuthorization` and return its `gatewayData` if valid.
   *
   * @param authorizationSerialized
   * @throws InvalidMessageError if the authorization is malformed, invalid or expired
   */
  public async verifyEndpointRegistrationAuthorization(
    authorizationSerialized: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    const authorization = await PrivateNodeRegistrationAuthorization.deserialize(
      authorizationSerialized,
      this.node.identityKeyPair.publicKey,
    );
    return authorization.gatewayData;
  }

  /**
   * Return a `PrivateNodeRegistration` including a new certificate for `endpointPublicKey`.
   *
   * @param endpointPublicKey
   * @return The serialization of the registration
   */
  public async registerEndpoint(endpointPublicKey: CryptoKey): Promise<ArrayBuffer> {
    const endpointCertificate = await issueEndpointCertificate({
      issuerCertificate: this.deliveryAuthPath.leafCertificate,
      issuerPrivateKey: this.node.identityKeyPair.privateKey,
      subjectPublicKey: endpointPublicKey,
      validityEndDate: addMonths(new Date(), 6),
    });
    const registration = new PrivateNodeRegistration(
      endpointCertificate,
      this.deliveryAuthPath.leafCertificate,
      this.peer.internetAddress,
    );
    return registration.serialize();
  }

  public async generateCCA(): Promise<ArrayBuffer> {
    const now = new Date();
    const startDate = subMinutes(now, CLOCK_DRIFT_TOLERANCE_MINUTES);
    const endDate = addDays(now, OUTBOUND_CARGO_TTL_DAYS);

    const cdaIssuer = await this.getOrCreateCDAIssuer();
    const cargoDeliveryAuthorization = await issueGatewayCertificate({
      issuerCertificate: cdaIssuer,
      issuerPrivateKey: this.node.identityKeyPair.privateKey,
      subjectPublicKey: this.peer.identityPublicKey,
      validityEndDate: endDate,
    });
    const ccr = new CargoCollectionRequest(cargoDeliveryAuthorization);
    return this.makeMessage(ccr, CargoCollectionAuthorization, {
      creationDate: startDate,
      ttl: differenceInSeconds(endDate, startDate),
    });
  }
}
