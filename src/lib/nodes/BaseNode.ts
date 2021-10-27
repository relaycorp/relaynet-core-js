import { SessionEnvelopedData } from '../crypto_wrappers/cms/envelopedData';
import { PrivateKeyStore } from '../keyStores/privateKeyStore';
import { PublicKeyStore } from '../keyStores/publicKeyStore';
import PayloadPlaintext from '../messages/payloads/PayloadPlaintext';
import RAMFMessage from '../messages/RAMFMessage';
import { NodeError } from './errors';
import { NodeCryptoOptions } from './NodeCryptoOptions';

export abstract class BaseNode<Payload extends PayloadPlaintext> {
  constructor(
    protected privateKeyStore: PrivateKeyStore,
    protected publicKeyStore: PublicKeyStore,
    protected cryptoOptions: Partial<NodeCryptoOptions> = {},
  ) {}

  /**
   * Encrypt and serialize the `payload`.
   *
   * Also store the new ephemeral session key.
   *
   * @param payload
   * @param peerPrivateAddress
   */
  public async wrapMessagePayload<P extends Payload>(
    payload: P | ArrayBuffer,
    peerPrivateAddress: string,
  ): Promise<ArrayBuffer> {
    const recipientSessionKey = await this.publicKeyStore.fetchLastSessionKey(peerPrivateAddress);
    if (!recipientSessionKey) {
      throw new NodeError(`Could not find session key for peer ${peerPrivateAddress}`);
    }
    const { envelopedData, dhKeyId, dhPrivateKey } = await SessionEnvelopedData.encrypt(
      payload instanceof ArrayBuffer ? payload : payload.serialize(),
      recipientSessionKey,
      this.cryptoOptions.encryption,
    );
    await this.privateKeyStore.saveSubsequentSessionKey(
      dhPrivateKey,
      Buffer.from(dhKeyId),
      peerPrivateAddress,
    );
    return envelopedData.serialize();
  }

  /**
   * Decrypt and return the payload in the `message`.
   *
   * Also store the session key, if using the channel session protocol.
   *
   * @param message
   */
  public async unwrapMessagePayload<P extends Payload>(message: RAMFMessage<P>): Promise<P> {
    const unwrapResult = await message.unwrapPayload(this.privateKeyStore);

    // If the sender uses channel session, store its public key for later use.
    if (unwrapResult.senderSessionKey) {
      await this.publicKeyStore.saveSessionKey(
        unwrapResult.senderSessionKey,
        await message.senderCertificate.calculateSubjectPrivateAddress(),
        message.creationDate,
      );
    }

    return unwrapResult.payload;
  }
}
