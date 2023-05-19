import { SessionEnvelopedData } from '../../crypto/cms/envelopedData';
import { KeyStoreSet } from '../../keyStores/KeyStoreSet';
import { PayloadPlaintext } from '../../messages/payloads/PayloadPlaintext';
import { Recipient } from '../../messages/Recipient';
import { NodeError } from '../errors';
import { NodeCryptoOptions } from '../NodeCryptoOptions';
import { Node } from '../Node';
import { Peer, PeerInternetAddress } from '../peer';
import { CertificationPath } from '../../pki/CertificationPath';
import { RAMFMessageConstructor } from '../../messages/RAMFMessageConstructor';
import { MessageOptions } from '../../messages/RAMFMessage';

export abstract class Channel<
  Payload extends PayloadPlaintext,
  PeerAddress extends PeerInternetAddress,
> {
  // noinspection TypeScriptAbstractClassConstructorCanBeMadeProtected
  constructor(
    public readonly node: Node<Payload, PeerAddress>,
    public readonly peer: Peer<PeerAddress>,
    public readonly deliveryAuthPath: CertificationPath,
    public readonly keyStores: KeyStoreSet,
    public cryptoOptions: Partial<NodeCryptoOptions> = {},
  ) {}

  /**
   * Generate and serialise a message with the given `payload`.
   * @param payload The payload to encrypt and encapsulate
   * @param messageConstructor The message class constructor
   * @param options
   */
  public async makeMessage(
    payload: Payload | ArrayBuffer,
    messageConstructor: RAMFMessageConstructor<Payload>,
    options: Partial<Omit<MessageOptions, 'senderCaCertificateChain'>> = {},
  ): Promise<ArrayBuffer> {
    const payloadSerialised = await this.wrapMessagePayload(payload);
    const message = new messageConstructor(
      this.getOutboundRAMFRecipient(),
      this.deliveryAuthPath.leafCertificate,
      Buffer.from(payloadSerialised),
      {
        ...options,
        senderCaCertificateChain: this.deliveryAuthPath.certificateAuthorities,
      },
    );
    return message.serialize(this.node.identityKeyPair.privateKey, this.cryptoOptions.signature);
  }

  /**
   * Encrypt and serialize the `payload`.
   *
   * @param payload
   *
   * Also store the new ephemeral session key.
   */
  private async wrapMessagePayload(payload: Payload | ArrayBuffer): Promise<ArrayBuffer> {
    const recipientSessionKey = await this.keyStores.publicKeyStore.retrieveLastSessionKey(
      this.peer.id,
    );
    if (!recipientSessionKey) {
      throw new NodeError(`Could not find session key for peer ${this.peer.id}`);
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
      this.peer.id,
    );
    return envelopedData.serialize();
  }

  public getOutboundRAMFRecipient(): Recipient {
    return { id: this.peer.id };
  }
}
