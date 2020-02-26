import bufferToArray from 'buffer-to-arraybuffer';

import { EnvelopedData, SessionEnvelopedData } from '../crypto_wrappers/cms/envelopedData';
import Message from '../messages/Message';
import { PrivateKeyStore } from '../privateKeyStore';

export default abstract class BaseNode<M extends Message> {
  constructor(protected readonly keyStore: PrivateKeyStore) {}

  protected async decryptPayload(message: M): Promise<ArrayBuffer> {
    const payload = EnvelopedData.deserialize(bufferToArray(message.payloadSerialized));
    const keyId = payload.getRecipientKeyId();
    const privateKey =
      payload instanceof SessionEnvelopedData
        ? await this.keyStore.fetchSessionKey(keyId, message.senderCertificate)
        : await this.keyStore.fetchNodeKey(keyId);
    return payload.decrypt(privateKey);
  }
}
