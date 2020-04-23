import { OriginatorSessionKey } from '../crypto_wrappers/cms/envelopedData';
import { derDeserializeECDHPublicKey, derSerializePublicKey } from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import PublicKeyStoreError from './PublicKeyStoreError';

export interface SessionPublicKeyData {
  readonly publicKeyId: Buffer;
  readonly publicKeyDer: Buffer;
  readonly publicKeyCreationTime: Date;
}

export abstract class PublicKeyStore {
  public async fetchLastSessionKey(peerCertificate: Certificate): Promise<OriginatorSessionKey> {
    const peerPrivateAddress = await peerCertificate.calculateSubjectPrivateAddress();
    const keyData = await this.fetchKeyDataOrThrowError(peerPrivateAddress);
    const publicKey = await derDeserializeECDHPublicKey(keyData.publicKeyDer);
    return { publicKey, keyId: keyData.publicKeyId };
  }

  public async saveSessionKey(
    key: OriginatorSessionKey,
    peerCertificate: Certificate,
    creationTime: Date,
  ): Promise<void> {
    const peerPrivateAddress = await peerCertificate.calculateSubjectPrivateAddress();

    // tslint:disable-next-line:no-let
    let priorKeyData: SessionPublicKeyData | undefined;
    try {
      priorKeyData = await this.fetchKey(peerPrivateAddress);
    } catch (_) {
      priorKeyData = undefined;
    }

    if (priorKeyData === undefined || priorKeyData.publicKeyCreationTime < creationTime) {
      const keyData: SessionPublicKeyData = {
        publicKeyCreationTime: creationTime,
        publicKeyDer: await derSerializePublicKey(key.publicKey),
        publicKeyId: key.keyId,
      };
      await this.saveKey(keyData, peerPrivateAddress);
    }
  }

  protected abstract async fetchKey(peerPrivateAddress: string): Promise<SessionPublicKeyData>;

  protected abstract async saveKey(
    keyData: SessionPublicKeyData,
    peerPrivateAddress: string,
  ): Promise<void>;

  private async fetchKeyDataOrThrowError(
    peerPrivateAddress: string,
  ): Promise<SessionPublicKeyData> {
    try {
      return await this.fetchKey(peerPrivateAddress);
    } catch (error) {
      throw new PublicKeyStoreError(error, 'Failed to retrieve key');
    }
  }
}
