import { addDays, subMinutes } from 'date-fns';

import {
  getPrivateAddressFromIdentityKey,
  getRSAPublicKeyFromPrivate,
} from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { issueGatewayCertificate } from '../pki';
import { PrivatePublicGatewayChannel } from './channels/PrivatePublicGatewayChannel';
import { Gateway } from './Gateway';

export class PrivateGateway extends Gateway {
  public async getChannelWithPublicGateway(
    publicGatewayPrivateAddress: string,
    publicGatewayPublicAddress: string,
  ): Promise<PrivatePublicGatewayChannel | null> {
    const publicGatewayPublicKey = await this.keyStores.publicKeyStore.retrieveIdentityKey(
      publicGatewayPrivateAddress,
    );
    if (!publicGatewayPublicKey) {
      return null;
    }

    const privateGatewayDeliveryAuth = await this.keyStores.certificateStore.retrieveLatest(
      await getPrivateAddressFromIdentityKey(this.privateKey),
      publicGatewayPrivateAddress,
    );
    if (!privateGatewayDeliveryAuth) {
      return null;
    }

    return new PrivatePublicGatewayChannel(
      this,
      this.privateKey,
      privateGatewayDeliveryAuth,
      publicGatewayPrivateAddress,
      publicGatewayPublicKey,
      publicGatewayPublicAddress,
      this.keyStores,
    );
  }

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
