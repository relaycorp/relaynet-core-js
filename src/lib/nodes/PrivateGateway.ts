import { addDays, subMinutes } from 'date-fns';

import {
  getPrivateAddressFromIdentityKey,
  getRSAPublicKeyFromPrivate,
} from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { issueGatewayCertificate } from '../pki';
import { Gateway } from './Gateway';

export class PrivateGateway extends Gateway {
  /**
   * @internal
   */
  public async getOrCreateCDAIssuer(): Promise<Certificate> {
    const now = new Date();

    const publicKey = await getRSAPublicKeyFromPrivate(this.privateKey);
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
      issuerPrivateKey: this.privateKey,
      subjectPublicKey: publicKey,
      validityEndDate: addDays(now, 180),
      validityStartDate: subMinutes(now, 90),
    });
    await this.keyStores.certificateStore.save(issuer, privateAddress);
    return issuer;
  }
}
