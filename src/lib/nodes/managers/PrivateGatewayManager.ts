import { PrivateGateway } from '../PrivateGateway';
import { GatewayManager } from './GatewayManager';

export class PrivateGatewayManager extends GatewayManager {
  public async get(privateAddress: string): Promise<PrivateGateway | null> {
    const nodePrivateKey = await this.keyStores.privateKeyStore.retrieveIdentityKey(privateAddress);
    if (!nodePrivateKey) {
      return null;
    }
    return new PrivateGateway(privateAddress, nodePrivateKey, this.keyStores, this.cryptoOptions);
  }
}
