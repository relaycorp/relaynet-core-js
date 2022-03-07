import { addDays, differenceInSeconds, subMinutes } from 'date-fns';

import { getPrivateAddressFromIdentityKey } from '../../crypto_wrappers/keys';
import Certificate from '../../crypto_wrappers/x509/Certificate';
import { KeyStoreSet } from '../../keyStores/KeyStoreSet';
import { CargoCollectionAuthorization } from '../../messages/CargoCollectionAuthorization';
import { CargoCollectionRequest } from '../../messages/payloads/CargoCollectionRequest';
import { issueGatewayCertificate } from '../../pki';
import { PrivateGateway } from '../PrivateGateway';
import { Channel } from './Channel';

const CLOCK_DRIFT_TOLERANCE_MINUTES = 90;
const OUTBOUND_CARGO_TTL_DAYS = 14;

/**
 * Channel between a private gateway (the node) and its public gateway (the peer).
 */
export class PrivatePublicGatewayChannel extends Channel<PrivateGateway> {
  protected readonly publicGatewayPublicAddress: string;
  /**
   * @internal
   */
  constructor(
    node: PrivateGateway,
    nodePrivateKey: CryptoKey,
    nodeDeliveryAuth: Certificate,
    publicGatewayPublicKey: CryptoKey,
    publicGatewayPublicAddress: string,
    keyStores: KeyStoreSet,
  ) {
    super(node, nodePrivateKey, nodeDeliveryAuth, publicGatewayPublicKey, keyStores);

    this.publicGatewayPublicAddress = `https://${publicGatewayPublicAddress}`;
  }

  public async generateCCA(): Promise<ArrayBuffer> {
    const now = new Date();
    const startDate = subMinutes(now, CLOCK_DRIFT_TOLERANCE_MINUTES);
    const endDate = addDays(now, OUTBOUND_CARGO_TTL_DAYS);

    const cdaIssuer = await this.node.getOrCreateCDAIssuer();
    const cargoDeliveryAuthorization = await issueGatewayCertificate({
      issuerCertificate: cdaIssuer,
      issuerPrivateKey: this.nodePrivateKey,
      subjectPublicKey: this.peerPublicKey,
      validityEndDate: endDate,
    });
    const ccr = new CargoCollectionRequest(cargoDeliveryAuthorization);
    const ccaPayload = await this.node.wrapMessagePayload(
      ccr,
      await getPrivateAddressFromIdentityKey(this.peerPublicKey),
    );
    const cca = new CargoCollectionAuthorization(
      this.publicGatewayPublicAddress,
      this.nodeDeliveryAuth,
      Buffer.from(ccaPayload),
      { creationDate: startDate, ttl: differenceInSeconds(endDate, startDate) },
    );
    return cca.serialize(this.nodePrivateKey);
  }
}
