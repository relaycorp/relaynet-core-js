import { SessionEnvelopedData } from '../../crypto_wrappers/cms/envelopedData';
import { getPrivateAddressFromIdentityKey } from '../../crypto_wrappers/keys';
import Certificate from '../../crypto_wrappers/x509/Certificate';
import { KeyStoreSet } from '../../keyStores/KeyStoreSet';
import PayloadPlaintext from '../../messages/payloads/PayloadPlaintext';
import { NodeError } from '../errors';
import { NodeCryptoOptions } from '../NodeCryptoOptions';

export abstract class Channel {
  // noinspection TypeScriptAbstractClassConstructorCanBeMadeProtected
  constructor(
    protected readonly nodePrivateKey: CryptoKey,
    public readonly nodeDeliveryAuth: Certificate,
    public readonly peerPrivateAddress: string,
    public readonly peerPublicKey: CryptoKey,
    protected readonly keyStores: KeyStoreSet,
    public cryptoOptions: Partial<NodeCryptoOptions> = {},
  ) {}

  /**
   * Encrypt and serialize the `payload`.
   *
   * @param payload
   *
   * Also store the new ephemeral session key.
   */
  public async wrapMessagePayload(payload: PayloadPlaintext | ArrayBuffer): Promise<ArrayBuffer> {
    const recipientSessionKey = await this.keyStores.publicKeyStore.retrieveLastSessionKey(
      this.peerPrivateAddress,
    );
    if (!recipientSessionKey) {
      throw new NodeError(`Could not find session key for peer ${this.peerPrivateAddress}`);
    }
    const { envelopedData, dhKeyId, dhPrivateKey } = await SessionEnvelopedData.encrypt(
      payload instanceof ArrayBuffer ? payload : payload.serialize(),
      recipientSessionKey,
      this.cryptoOptions.encryption,
    );
    await this.keyStores.privateKeyStore.saveSessionKey(
      dhPrivateKey,
      Buffer.from(dhKeyId),
      await this.getNodePrivateAddress(),
      this.peerPrivateAddress,
    );
    return envelopedData.serialize();
  }

  public abstract getOutboundRAMFAddress(): Promise<string>;

  protected async getNodePrivateAddress(): Promise<string> {
    return getPrivateAddressFromIdentityKey(this.nodePrivateKey);
  }
}
