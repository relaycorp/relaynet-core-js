import { Certificate } from '../crypto/x509/Certificate';
import { KeyStoreSet } from '../keyStores/KeyStoreSet';
import { PayloadPlaintext } from '../messages/payloads/PayloadPlaintext';
import { RAMFMessage } from '../messages/RAMFMessage';
import { SessionKey } from '../SessionKey';
import { SessionKeyPair } from '../SessionKeyPair';
import { NodeCryptoOptions } from './NodeCryptoOptions';
import { Signer } from './signatures/Signer';
import { InvalidMessageError } from '../messages/InvalidMessageError';
import { PeerInternetAddress } from './peer';
import { ChannelConstructor } from './channels/ChannelConstructor';
import { Channel } from './channels/Channel';
import { NodeError } from './errors';

export abstract class Node<
  Payload extends PayloadPlaintext,
  PeerAddress extends PeerInternetAddress,
> {
  protected abstract readonly channelConstructor: ChannelConstructor<Payload, PeerAddress>;

  constructor(
    public readonly id: string,
    public readonly identityKeyPair: CryptoKeyPair,
    public readonly keyStores: KeyStoreSet,
    public readonly cryptoOptions: Partial<NodeCryptoOptions>,
  ) {}

  /**
   * Generate and store a new session key.
   *
   * @param peerId The peer to bind the key to, unless it's an initial key
   */
  public async generateSessionKey(peerId?: string): Promise<SessionKey> {
    const { sessionKey, privateKey } = await SessionKeyPair.generate();
    await this.keyStores.privateKeyStore.saveSessionKey(
      privateKey,
      sessionKey.keyId,
      this.id,
      peerId,
    );
    return sessionKey;
  }

  public async getGSCSigner<S extends Signer>(
    peerId: string,
    signerClass: new (certificate: Certificate, privateKey: CryptoKey) => S,
  ): Promise<S | null> {
    const path = await this.keyStores.certificateStore.retrieveLatest(this.id, peerId);
    if (!path) {
      return null;
    }
    return new signerClass(path.leafCertificate, this.identityKeyPair.privateKey);
  }

  /**
   * Validate the `message` and report whether it's correctly bound for this node.
   * @param message The message to validate
   * @param trustedCertificates If authorisation should be verified
   * @throws {InvalidMessageError} If the message is invalid
   */
  public async validateMessage(
    message: RAMFMessage<Payload>,
    trustedCertificates?: readonly Certificate[],
  ): Promise<void> {
    if (trustedCertificates) {
      await message.validate(trustedCertificates);
    } else {
      await message.validate();
    }

    if (message.recipient.id !== this.id) {
      throw new InvalidMessageError(`Message is bound for another node (${message.recipient.id})`);
    }
  }

  /**
   * Decrypt and return the payload in the `message`.
   *
   * Also store the session key from the sender.
   *
   * @param message
   */
  public async unwrapMessagePayload<P extends Payload>(message: RAMFMessage<P>): Promise<P> {
    const unwrapResult = await message.unwrapPayload(this.keyStores.privateKeyStore);

    await this.keyStores.publicKeyStore.saveSessionKey(
      unwrapResult.senderSessionKey,
      await message.senderCertificate.calculateSubjectId(),
      message.creationDate,
    );

    return unwrapResult.payload;
  }

  public async getChannel(
    peerId: string,
    peerInternetAddress: PeerAddress,
  ): Promise<Channel<Payload, PeerAddress> | null> {
    const peerPublicKey = await this.keyStores.publicKeyStore.retrieveIdentityKey(peerId);
    if (!peerPublicKey) {
      return null;
    }

    const deliveryAuth = await this.keyStores.certificateStore.retrieveLatest(this.id, peerId);
    if (!deliveryAuth) {
      throw new NodeError(
        `Could not find delivery authorization for peer ${peerId}; it might have have expired`,
      );
    }

    const peer = {
      id: peerId,
      identityPublicKey: peerPublicKey,
      internetAddress: peerInternetAddress,
    };
    return new this.channelConstructor(
      this,
      peer,
      deliveryAuth,
      this.keyStores,
      this.cryptoOptions,
    );
  }
}
