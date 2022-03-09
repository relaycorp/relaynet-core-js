import { getPrivateAddressFromIdentityKey } from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { SessionKey } from '../SessionKey';
import { PrivatePublicGatewayChannel } from './channels/PrivatePublicGatewayChannel';
import { Gateway } from './Gateway';

export class PrivateGateway extends Gateway {
  public async savePublicGatewayChannel(
    deliveryAuthorization: Certificate,
    publicGatewayIdentityPublicKey: CryptoKey,
    publicGatewaySessionPublicKey: SessionKey,
  ): Promise<void> {
    throw new Error(
      'impl' +
        deliveryAuthorization +
        publicGatewayIdentityPublicKey +
        publicGatewaySessionPublicKey,
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
