import { derDeserializeECDHPublicKey, derSerializePublicKey } from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import PublicKeyStoreError from './PublicKeyStoreError';

export interface PublicKeyData {
  readonly publicKeyDer: Buffer;
  readonly publicKeyCreationTime: Date;
}

export abstract class PublicKeyStore {
  public async fetchLastSessionKey(peerCertificate: Certificate): Promise<CryptoKey> {
    const peerPrivateAddress = await peerCertificate.calculateSubjectPrivateAddress();
    const keyData = await this.fetchKeyDataOrThrowError(peerPrivateAddress);
    return derDeserializeECDHPublicKey(keyData.publicKeyDer);
  }

  public async saveSessionKey(
    key: CryptoKey,
    peerCertificate: Certificate,
    creationTime: Date,
  ): Promise<void> {
    const peerPrivateAddress = await peerCertificate.calculateSubjectPrivateAddress();

    // tslint:disable-next-line:no-let
    let priorKeyData: PublicKeyData | undefined;
    try {
      priorKeyData = await this.fetchKey(peerPrivateAddress);
    } catch (_) {
      priorKeyData = undefined;
    }

    if (priorKeyData === undefined || priorKeyData.publicKeyCreationTime < creationTime) {
      const keyData: PublicKeyData = {
        publicKeyCreationTime: creationTime,
        publicKeyDer: await derSerializePublicKey(key),
      };
      await this.saveKey(keyData, peerPrivateAddress);
    }
  }

  protected abstract async fetchKey(peerPrivateAddress: string): Promise<PublicKeyData>;

  protected abstract async saveKey(
    keyData: PublicKeyData,
    peerPrivateAddress: string,
  ): Promise<void>;

  private async fetchKeyDataOrThrowError(peerPrivateAddress: string): Promise<PublicKeyData> {
    try {
      return await this.fetchKey(peerPrivateAddress);
    } catch (error) {
      throw new PublicKeyStoreError(error, 'Failed to retrieve key');
    }
  }
}
