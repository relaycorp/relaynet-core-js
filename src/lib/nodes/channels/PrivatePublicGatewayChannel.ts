import { addDays, differenceInSeconds, subMinutes } from 'date-fns';

import Certificate from '../../crypto_wrappers/x509/Certificate';
import { KeyStoreSet } from '../../keyStores/KeyStoreSet';
import { CargoCollectionAuthorization } from '../../messages/CargoCollectionAuthorization';
import { CargoCollectionRequest } from '../../messages/payloads/CargoCollectionRequest';
import { issueGatewayCertificate } from '../../pki';
import { PrivateGatewayChannel } from './PrivateGatewayChannel';

const CLOCK_DRIFT_TOLERANCE_MINUTES = 90;
const OUTBOUND_CARGO_TTL_DAYS = 14;

/**
 * Channel between a private gateway (the node) and its public gateway (the peer).
 */
export class PrivatePublicGatewayChannel extends PrivateGatewayChannel {
  /**
   * @internal
   */
  constructor(
    privateGatewayPrivateKey: CryptoKey,
    privateGatewayDeliveryAuth: Certificate,
    publicGatewayPrivateAddress: string,
    publicGatewayPublicKey: CryptoKey,
    public readonly publicGatewayPublicAddress: string,
    keyStores: KeyStoreSet,
  ) {
    super(
      privateGatewayPrivateKey,
      privateGatewayDeliveryAuth,
      publicGatewayPrivateAddress,
      publicGatewayPublicKey,
      keyStores,
    );
  }

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
      `https://${this.publicGatewayPublicAddress}`,
      this.nodeDeliveryAuth,
      Buffer.from(ccaPayload),
      { creationDate: startDate, ttl: differenceInSeconds(endDate, startDate) },
    );
    return cca.serialize(this.nodePrivateKey);
  }
}
