import { KeyStoreSet } from '../../keyStores/KeyStoreSet';
import { NodeCryptoOptions } from '../NodeCryptoOptions';
import { PrivateGateway } from '../PrivateGateway';
import { GatewayManager } from './GatewayManager';

type PrivateGatewayConstructor<G extends PrivateGateway> = new (
  privateAddress: string,
  identityPrivateKey: CryptoKey,
  keyStores: KeyStoreSet,
  cryptoOptions: Partial<NodeCryptoOptions>,
) => G;

export class PrivateGatewayManager extends GatewayManager {
  /**
   * Get private gateway by `privateAddress`.
   *
   * @param privateAddress
   */
  public async get(privateAddress: string): Promise<PrivateGateway | null>;
  /**
   * Get private gateway by `privateAddress` but return instance of custom
   * `customPrivateGatewayClass`.
   *
   * @param privateAddress
   * @param customPrivateGatewayClass
   */
  public async get<G extends PrivateGateway>(
    privateAddress: string,
    customPrivateGatewayClass: PrivateGatewayConstructor<G>,
  ): Promise<G | null>;
  public async get<G extends PrivateGateway>(
    privateAddress: string,
    privateGatewayConstructor?: PrivateGatewayConstructor<G>,
  ): Promise<G | PrivateGateway | null> {
    const nodePrivateKey = await this.keyStores.privateKeyStore.retrieveIdentityKey(privateAddress);
    if (!nodePrivateKey) {
      return null;
    }
    const constructor = privateGatewayConstructor ?? PrivateGateway;
    return new constructor(privateAddress, nodePrivateKey, this.keyStores, this.cryptoOptions);
  }
}
