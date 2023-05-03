import { getRSAPublicKeyFromPrivate } from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { KeyStoreSet } from '../keyStores/KeyStoreSet';
import PayloadPlaintext from '../messages/payloads/PayloadPlaintext';
import RAMFMessage from '../messages/RAMFMessage';
import { SessionKey } from '../SessionKey';
import { SessionKeyPair } from '../SessionKeyPair';
import { NodeCryptoOptions } from './NodeCryptoOptions';
import { Signer } from './signatures/Signer';

export abstract class Node<Payload extends PayloadPlaintext> {
  constructor(
    public readonly id: string,
    public readonly identityPrivateKey: CryptoKey,
    public readonly keyStores: KeyStoreSet,
    protected readonly cryptoOptions: Partial<NodeCryptoOptions>,
  ) {}

  public async getIdentityPublicKey(): Promise<CryptoKey> {
    return getRSAPublicKeyFromPrivate(this.identityPrivateKey);
  }

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
    return new signerClass(path.leafCertificate, this.identityPrivateKey);
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
}
