import Certificate from '../crypto_wrappers/x509/Certificate';
import { KeyStoreSet } from '../keyStores/KeyStoreSet';
import PayloadPlaintext from '../messages/payloads/PayloadPlaintext';
import RAMFMessage from '../messages/RAMFMessage';
import { NodeCryptoOptions } from './NodeCryptoOptions';
import { Signer } from './signatures/Signer';

export abstract class Node<Payload extends PayloadPlaintext> {
  constructor(
    public readonly privateAddress: string,
    protected readonly privateKey: CryptoKey,
    protected readonly keyStores: KeyStoreSet,
    protected readonly cryptoOptions: Partial<NodeCryptoOptions>,
  ) {}

  public async getGSCSigner<S extends Signer>(
    peerPrivateAddress: string,
    signerClass: new (certificate: Certificate, privateKey: CryptoKey) => S,
  ): Promise<S | null> {
    const certificate = await this.keyStores.certificateStore.retrieveLatest(
      this.privateAddress,
      peerPrivateAddress,
    );
    if (!certificate) {
      return null;
    }
    return new signerClass(certificate, this.privateKey);
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
      await message.senderCertificate.calculateSubjectPrivateAddress(),
      message.creationDate,
    );

    return unwrapResult.payload;
  }
}