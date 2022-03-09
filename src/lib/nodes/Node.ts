import Certificate from '../crypto_wrappers/x509/Certificate';
import { KeyStoreSet } from '../keyStores/KeyStoreSet';
import PayloadPlaintext from '../messages/payloads/PayloadPlaintext';
import RAMFMessage from '../messages/RAMFMessage';
import { NodeCryptoOptions } from './NodeCryptoOptions';
import { Signer } from './signatures/Signer';
import { Verifier } from './signatures/Verifier';

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

  public async getGCSVerifier<V extends Verifier>(
    peerPrivateAddress: string,
    verifierClass: new (trustedCertificates: readonly Certificate[]) => V,
  ): Promise<V | null> {
    const trustedCertificates = await this.keyStores.certificateStore.retrieveAll(
      this.privateAddress,
      peerPrivateAddress,
    );
    if (trustedCertificates.length === 0) {
      return null;
    }
    return new verifierClass(trustedCertificates);
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
