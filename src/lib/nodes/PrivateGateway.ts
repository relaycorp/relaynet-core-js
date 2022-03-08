import { getPrivateAddressFromIdentityKey } from '../crypto_wrappers/keys';
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
