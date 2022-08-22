import { SessionEnvelopedData } from '../../crypto_wrappers/cms/envelopedData';
import { getIdFromIdentityKey } from '../../crypto_wrappers/keys';
import Certificate from '../../crypto_wrappers/x509/Certificate';
import { KeyStoreSet } from '../../keyStores/KeyStoreSet';
import PayloadPlaintext from '../../messages/payloads/PayloadPlaintext';
import { Recipient } from '../../messages/Recipient';
import { NodeError } from '../errors';
import { NodeCryptoOptions } from '../NodeCryptoOptions';

export abstract class Channel {
  // noinspection TypeScriptAbstractClassConstructorCanBeMadeProtected
  constructor(
    protected readonly nodePrivateKey: CryptoKey,
    public readonly nodeDeliveryAuth: Certificate,
    public readonly peerId: string,
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
      this.peerId,
    );
    if (!recipientSessionKey) {
      throw new NodeError(`Could not find session key for peer ${this.peerId}`);
    }
    const { envelopedData, dhKeyId, dhPrivateKey } = await SessionEnvelopedData.encrypt(
      payload instanceof ArrayBuffer ? payload : payload.serialize(),
      recipientSessionKey,
      this.cryptoOptions.encryption,
    );
    await this.keyStores.privateKeyStore.saveSessionKey(
      dhPrivateKey,
      Buffer.from(dhKeyId),
      await this.getNodeId(),
      this.peerId,
    );
    return envelopedData.serialize();
  }

  public getOutboundRAMFRecipient(): Recipient {
    return { id: this.peerId };
  }

  protected async getNodeId(): Promise<string> {
    return getIdFromIdentityKey(this.nodePrivateKey);
  }
}
