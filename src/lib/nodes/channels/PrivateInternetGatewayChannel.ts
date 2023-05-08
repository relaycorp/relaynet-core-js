import { addDays, addMonths, differenceInSeconds, subMinutes } from 'date-fns';

import { PrivateNodeRegistration } from '../../bindings/gsc/PrivateNodeRegistration';
import { PrivateNodeRegistrationAuthorization } from '../../bindings/gsc/PrivateNodeRegistrationAuthorization';
import { getRSAPublicKeyFromPrivate } from '../../crypto/keys/generation';
import { Certificate } from '../../crypto/x509/Certificate';
import { KeyStoreSet } from '../../keyStores/KeyStoreSet';
import { CargoCollectionAuthorization } from '../../messages/CargoCollectionAuthorization';
import { CargoCollectionRequest } from '../../messages/payloads/CargoCollectionRequest';
import { Recipient } from '../../messages/Recipient';
import { issueEndpointCertificate, issueGatewayCertificate } from '../../pki/issuance';
import { NodeCryptoOptions } from '../NodeCryptoOptions';
import { PrivateGatewayChannel } from './PrivateGatewayChannel';

const CLOCK_DRIFT_TOLERANCE_MINUTES = 90;
const OUTBOUND_CARGO_TTL_DAYS = 14;

/**
 * Channel between a private gateway (the node) and its Internet gateway (the peer).
 */
export class PrivateInternetGatewayChannel extends PrivateGatewayChannel {
  /**
   * @internal
   */
  constructor(
    privateGatewayPrivateKey: CryptoKey,
    privateGatewayDeliveryAuth: Certificate,
    internetGatewayId: string,
    internetGatewayPublicKey: CryptoKey,
    public readonly internetGatewayInternetAddress: string,
    keyStores: KeyStoreSet,
    cryptoOptions: Partial<NodeCryptoOptions>,
  ) {
    super(
      privateGatewayPrivateKey,
      privateGatewayDeliveryAuth,
      internetGatewayId,
      internetGatewayPublicKey,
      keyStores,
      cryptoOptions,
    );
  }

  override getOutboundRAMFRecipient(): Recipient {
    return {
      ...super.getOutboundRAMFRecipient(),
      internetAddress: this.internetGatewayInternetAddress,
    };
  }

  //region Private endpoint registration

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
    return authorization.serialize(this.nodePrivateKey);
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
    const publicKey = await getRSAPublicKeyFromPrivate(this.nodePrivateKey);
    const authorization = await PrivateNodeRegistrationAuthorization.deserialize(
      authorizationSerialized,
      publicKey,
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
      issuerCertificate: this.nodeDeliveryAuth,
      issuerPrivateKey: this.nodePrivateKey,
      subjectPublicKey: endpointPublicKey,
      validityEndDate: addMonths(new Date(), 6),
    });
    const registration = new PrivateNodeRegistration(
      endpointCertificate,
      this.nodeDeliveryAuth,
      this.internetGatewayInternetAddress,
    );
    return registration.serialize();
  }

  //endregion

  public async generateCCA(): Promise<ArrayBuffer> {
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
    const cca = new CargoCollectionAuthorization(
      this.getOutboundRAMFRecipient(),
      this.nodeDeliveryAuth,
      Buffer.from(ccaPayload),
      { creationDate: startDate, ttl: differenceInSeconds(endDate, startDate) },
    );
    return cca.serialize(this.nodePrivateKey);
  }
}
