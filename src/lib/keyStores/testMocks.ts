// tslint:disable:max-classes-per-file no-object-mutation

import { derSerializePrivateKey, getPublicKeyDigestHex } from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { PrivateKeyData, PrivateKeyStore } from './privateKeyStore';
import { PublicKeyStore, SessionPublicKeyData } from './publicKeyStore';

export class MockPrivateKeyStore extends PrivateKeyStore {
  // tslint:disable-next-line:readonly-keyword
  public keys: { [key: string]: PrivateKeyData } = {};

  constructor(protected readonly failOnSave = false, protected readonly failOnFetch = false) {
    super();
  }

  public clear(): void {
    this.keys = {};
  }

  public async registerNodeKey(privateKey: CryptoKey, certificate: Certificate): Promise<void> {
    // tslint:disable-next-line:no-object-mutation
    this.keys[certificate.getSerialNumberHex()] = {
      certificateDer: Buffer.from(certificate.serialize()),
      keyDer: await derSerializePrivateKey(privateKey),
      type: 'node',
    };
  }

  public async registerInitialSessionKey(
    privateKey: CryptoKey,
    certificate: Certificate,
  ): Promise<void> {
    this.keys[certificate.getSerialNumberHex()] = {
      certificateDer: Buffer.from(certificate.serialize()),
      keyDer: await derSerializePrivateKey(privateKey),
      type: 'session-initial',
    };
  }

  public async registerSubsequentSessionKey(
    privateKey: CryptoKey,
    keyId: string,
    recipientCertificate: Certificate,
  ): Promise<void> {
    this.keys[keyId] = {
      keyDer: await derSerializePrivateKey(privateKey),
      recipientPublicKeyDigest: await getPublicKeyDigestHex(
        await recipientCertificate.getPublicKey(),
      ),
      type: 'session-subsequent',
    };
  }

  protected async fetchKey(keyId: string): Promise<PrivateKeyData | null> {
    if (this.failOnFetch) {
      throw new Error('Denied');
    }
    return this.keys[keyId] ?? null;
  }

  protected async saveKey(privateKeyData: PrivateKeyData, keyId: string): Promise<void> {
    if (this.failOnSave) {
      throw new Error('Denied');
    }
    this.keys[keyId] = privateKeyData;
  }
}

export class MockPublicKeyStore extends PublicKeyStore {
  // tslint:disable-next-line:readonly-keyword
  public keys: { [key: string]: SessionPublicKeyData } = {};

  constructor(protected readonly failOnSave = false, protected fetchError?: Error) {
    super();
  }

  public clear(): void {
    this.keys = {};
  }

  public registerKey(keyData: SessionPublicKeyData, peerPrivateAddress: string): void {
    this.keys[peerPrivateAddress] = keyData;
  }

  protected async fetchKey(peerPrivateAddress: string): Promise<SessionPublicKeyData | null> {
    if (this.fetchError) {
      throw this.fetchError;
    }
    const keyData = this.keys[peerPrivateAddress];
    return keyData ?? null;
  }

  protected async saveKey(
    keyData: SessionPublicKeyData,
    peerPrivateAddress: string,
  ): Promise<void> {
    if (this.failOnSave) {
      throw new Error('Denied');
    }
    this.keys[peerPrivateAddress] = keyData;
  }
}
