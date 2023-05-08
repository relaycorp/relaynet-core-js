import { addDays, subMinutes } from 'date-fns';

import { getIdFromIdentityKey, getRSAPublicKeyFromPrivate } from '../../crypto/keys';
import { Certificate } from '../../crypto/x509/Certificate';
import { CertificationPath } from '../../pki/CertificationPath';
import { issueGatewayCertificate } from '../../pki/issuance';
import { GatewayChannel } from './GatewayChannel';

/**
 * Channel whose node is a private gateway.
 */
export abstract class PrivateGatewayChannel extends GatewayChannel {
  public async getOrCreateCDAIssuer(): Promise<Certificate> {
    const now = new Date();

    const publicKey = await getRSAPublicKeyFromPrivate(this.nodePrivateKey);
    const nodeId = await getIdFromIdentityKey(publicKey);

    const existingIssuerPath = await this.keyStores.certificateStore.retrieveLatest(nodeId, nodeId);
    if (existingIssuerPath) {
      const minExpiryDate = addDays(now, 90);
      if (minExpiryDate <= existingIssuerPath.leafCertificate.expiryDate) {
        return existingIssuerPath.leafCertificate;
      }
    }

    const issuer = await issueGatewayCertificate({
      issuerPrivateKey: this.nodePrivateKey,
      subjectPublicKey: publicKey,
      validityEndDate: addDays(now, 180),
      validityStartDate: subMinutes(now, 90),
    });
    const path = new CertificationPath(issuer, []);
    await this.keyStores.certificateStore.save(path, nodeId);
    return issuer;
  }

  /**
   * Get all CDA issuers in the channel.
   */
  public async getCDAIssuers(): Promise<readonly Certificate[]> {
    const publicKey = await getRSAPublicKeyFromPrivate(this.nodePrivateKey);
    const nodeId = await getIdFromIdentityKey(publicKey);
    const issuerPaths = await this.keyStores.certificateStore.retrieveAll(nodeId, nodeId);
    return issuerPaths.map((p) => p.leafCertificate);
  }
}
