import { addDays, subMinutes } from 'date-fns';

import {
  getPrivateAddressFromIdentityKey,
  getRSAPublicKeyFromPrivate,
} from '../../crypto_wrappers/keys';
import Certificate from '../../crypto_wrappers/x509/Certificate';
import { issueGatewayCertificate } from '../../pki';
import { GatewayChannel } from './GatewayChannel';

/**
 * Channel whose node is a private gateway.
 */
export abstract class PrivateGatewayChannel extends GatewayChannel {
  public async getOrCreateCDAIssuer(): Promise<Certificate> {
    const now = new Date();

    const publicKey = await getRSAPublicKeyFromPrivate(this.nodePrivateKey);
    const privateAddress = await getPrivateAddressFromIdentityKey(publicKey);

    const existingIssuer = await this.keyStores.certificateStore.retrieveLatest(
      privateAddress,
      privateAddress,
    );
    if (existingIssuer) {
      const minExpiryDate = addDays(now, 90);
      if (minExpiryDate <= existingIssuer.expiryDate) {
        return existingIssuer;
      }
    }

    const issuer = await issueGatewayCertificate({
      issuerPrivateKey: this.nodePrivateKey,
      subjectPublicKey: publicKey,
      validityEndDate: addDays(now, 180),
      validityStartDate: subMinutes(now, 90),
    });
    await this.keyStores.certificateStore.save(issuer, privateAddress);
    return issuer;
  }

  /**
   * Get all CDA issuers in the channel.
   */
  public async getCDAIssuers(): Promise<readonly Certificate[]> {
    const publicKey = await getRSAPublicKeyFromPrivate(this.nodePrivateKey);
    const privateAddress = await getPrivateAddressFromIdentityKey(publicKey);
    return this.keyStores.certificateStore.retrieveAll(privateAddress, privateAddress);
  }
}
