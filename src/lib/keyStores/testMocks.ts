// tslint:disable:max-classes-per-file no-object-mutation readonly-keyword

import { PrivateKeyStore, SessionPrivateKeyData } from './privateKeyStore';
import { PublicKeyStore, SessionPublicKeyData } from './publicKeyStore';

export class MockPrivateKeyStore extends PrivateKeyStore {
  public identityKeys: { [privateAddress: string]: Buffer } = {};

  public sessionKeys: { [keyId: string]: SessionPrivateKeyData } = {};

  constructor(protected readonly failOnSave = false, protected readonly failOnFetch = false) {
    super();
  }

  public clear(): void {
    this.identityKeys = {};
    this.sessionKeys = {};
  }

  protected async retrieveIdentityKeySerialized(privateAddress: string): Promise<Buffer | null> {
    if (this.failOnFetch) {
      throw new Error('Denied');
    }
    return this.identityKeys[privateAddress];
  }

  protected async saveIdentityKeySerialized(
    privateAddress: string,
    keySerialized: Buffer,
  ): Promise<void> {
    if (this.failOnSave) {
      throw new Error('Denied');
    }
    this.identityKeys[privateAddress] = keySerialized;
  }

  protected async saveSessionKeySerialized(
    keyId: string,
    keySerialized: Buffer,
    peerPrivateAddress?: string,
  ): Promise<void> {
    if (this.failOnSave) {
      throw new Error('Denied');
    }

    this.sessionKeys[keyId] = {
      keySerialized,
      peerPrivateAddress,
    };
  }

  protected async retrieveSessionKeyData(keyId: string): Promise<SessionPrivateKeyData | null> {
    if (this.failOnFetch) {
      throw new Error('Denied');
    }

    return this.sessionKeys[keyId] ?? null;
  }
}

export class MockPublicKeyStore extends PublicKeyStore {
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
