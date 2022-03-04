import { SessionEnvelopedData } from '../../crypto_wrappers/cms/envelopedData';
import { KeyStoreSet } from '../../keyStores/KeyStoreSet';
import PayloadPlaintext from '../../messages/payloads/PayloadPlaintext';
import RAMFMessage from '../../messages/RAMFMessage';
import { SessionKey } from '../../SessionKey';
import { SessionKeyPair } from '../../SessionKeyPair';
import { NodeError } from '../errors';
import { NodeCryptoOptions } from '../NodeCryptoOptions';

export abstract class NodeManager<Payload extends PayloadPlaintext> {
  constructor(
    protected keyStores: KeyStoreSet,
    protected cryptoOptions: Partial<NodeCryptoOptions> = {},
  ) {}

  /**
   * Generate and store a new session key.
   *
   * @param peerPrivateAddress The peer to bind the key to, unless it's an initial key
   */
  public async generateSessionKey(peerPrivateAddress?: string): Promise<SessionKey> {
    const { sessionKey, privateKey } = await SessionKeyPair.generate();

    if (peerPrivateAddress) {
      await this.keyStores.privateKeyStore.saveBoundSessionKey(
        privateKey,
        sessionKey.keyId,
        peerPrivateAddress,
      );
    } else {
      await this.keyStores.privateKeyStore.saveUnboundSessionKey(privateKey, sessionKey.keyId);
    }

    return sessionKey;
  }

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
    const recipientSessionKey = await this.keyStores.publicKeyStore.fetchLastSessionKey(
      peerPrivateAddress,
    );
    if (!recipientSessionKey) {
      throw new NodeError(`Could not find session key for peer ${peerPrivateAddress}`);
    }
    const { envelopedData, dhKeyId, dhPrivateKey } = await SessionEnvelopedData.encrypt(
      payload instanceof ArrayBuffer ? payload : payload.serialize(),
      recipientSessionKey,
      this.cryptoOptions.encryption,
    );
    await this.keyStores.privateKeyStore.saveBoundSessionKey(
      dhPrivateKey,
      Buffer.from(dhKeyId),
      peerPrivateAddress,
    );
    return envelopedData.serialize();
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
