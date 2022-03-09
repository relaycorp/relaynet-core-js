import { getPrivateAddressFromIdentityKey } from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { SessionKey } from '../SessionKey';
import { PrivatePublicGatewayChannel } from './channels/PrivatePublicGatewayChannel';
import { NodeError } from './errors';
import { Gateway } from './Gateway';

export class PrivateGateway extends Gateway {
  public async savePublicGatewayChannel(
    deliveryAuthorization: Certificate,
    publicGatewayIdentityCertificate: Certificate,
    publicGatewaySessionPublicKey: SessionKey,
  ): Promise<void> {
    try {
      await deliveryAuthorization.getCertificationPath([], [publicGatewayIdentityCertificate]);
    } catch (err) {
      throw new NodeError('Delivery authorization was not issued by public gateway');
    }

    const publicGatewayPrivateAddress = deliveryAuthorization.getIssuerPrivateAddress()!;
    await this.keyStores.certificateStore.save(deliveryAuthorization, publicGatewayPrivateAddress);
    await this.keyStores.publicKeyStore.saveIdentityKey(
      await publicGatewayIdentityCertificate.getPublicKey(),
    );
    await this.keyStores.publicKeyStore.saveSessionKey(
      publicGatewaySessionPublicKey,
      publicGatewayPrivateAddress,
      new Date(),
    );
  }

  public async retrievePublicGatewayChannel(
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
      this.privateKey,
      privateGatewayDeliveryAuth,
      publicGatewayPrivateAddress,
      publicGatewayPublicKey,
      publicGatewayPublicAddress,
      this.keyStores,
      this.cryptoOptions,
    );
  }
}
