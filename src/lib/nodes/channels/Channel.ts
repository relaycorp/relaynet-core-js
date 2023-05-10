import { SessionEnvelopedData } from '../../crypto/cms/envelopedData';
import { KeyStoreSet } from '../../keyStores/KeyStoreSet';
import { PayloadPlaintext } from '../../messages/payloads/PayloadPlaintext';
import { Recipient } from '../../messages/Recipient';
import { NodeError } from '../errors';
import { NodeCryptoOptions } from '../NodeCryptoOptions';
import { Node } from '../Node';
import { Certificate } from '../../crypto/x509/Certificate';

export abstract class Channel<Payload extends PayloadPlaintext> {
  // noinspection TypeScriptAbstractClassConstructorCanBeMadeProtected
  constructor(
    public readonly node: Node<Payload>,
    public readonly deliveryAuth: Certificate,
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
  public async wrapMessagePayload(payload: Payload | ArrayBuffer): Promise<ArrayBuffer> {
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
      this.node.id,
      this.peerId,
    );
    return envelopedData.serialize();
  }

  public getOutboundRAMFRecipient(): Recipient {
    return { id: this.peerId };
  }
}
