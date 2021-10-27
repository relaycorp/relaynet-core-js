import { PrivateKeyStore } from '../keyStores/privateKeyStore';
import { PublicKeyStore } from '../keyStores/publicKeyStore';
import PayloadPlaintext from '../messages/payloads/PayloadPlaintext';
import RAMFMessage from '../messages/RAMFMessage';
import { NodeOptions } from './NodeOptions';

export abstract class BaseNodeManager<Payload extends PayloadPlaintext> {
  constructor(
    protected privateKeyStore: PrivateKeyStore,
    protected publicKeyStore: PublicKeyStore,
    protected cryptoOptions: Partial<NodeOptions> = {},
  ) {}

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
