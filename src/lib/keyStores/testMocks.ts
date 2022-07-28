// tslint:disable:max-classes-per-file no-object-mutation readonly-keyword readonly-array

import { CertificationPath } from '../pki/CertificationPath';
import { CertificateStore } from './CertificateStore';
import { KeyStoreSet } from './KeyStoreSet';
import { PrivateKeyStore, SessionPrivateKeyData } from './PrivateKeyStore';
import { PublicKeyStore, SessionPublicKeyData } from './PublicKeyStore';

export class MockPrivateKeyStore extends PrivateKeyStore {
  public identityKeys: { [nodeId: string]: CryptoKey } = {};

  public sessionKeys: { [keyId: string]: SessionPrivateKeyData } = {};

  constructor(protected readonly failOnSave = false, protected readonly failOnFetch = false) {
    super();
  }

  public clear(): void {
    this.identityKeys = {};
    this.sessionKeys = {};
  }

  public async retrieveIdentityKey(nodeId: string): Promise<CryptoKey | null> {
    return this.identityKeys[nodeId] ?? null;
  }

  public async saveIdentityKey(nodeId: string, privateKey: CryptoKey): Promise<void> {
    if (this.failOnSave) {
      throw new Error('Denied');
    }
    this.identityKeys[nodeId] = privateKey;
  }

  protected async saveSessionKeySerialized(
    keyId: string,
    keySerialized: Buffer,
    nodeId: string,
    peerId?: string,
  ): Promise<void> {
    if (this.failOnSave) {
      throw new Error('Denied');
    }

    this.sessionKeys[keyId] = { keySerialized, peerId, nodeId };
  }

  protected async retrieveSessionKeyData(keyId: string): Promise<SessionPrivateKeyData | null> {
    if (this.failOnFetch) {
      throw new Error('Denied');
    }

    return this.sessionKeys[keyId] ?? null;
  }
}

export class MockPublicKeyStore extends PublicKeyStore {
  public identityKeys: { [peerId: string]: Buffer } = {};

  public sessionKeys: { [key: string]: SessionPublicKeyData } = {};

  constructor(protected readonly failOnSave = false, protected fetchError?: Error) {
    super();
  }

  public clear(): void {
    this.sessionKeys = {};
    this.identityKeys = {};
  }

  public registerSessionKey(keyData: SessionPublicKeyData, peerId: string): void {
    this.sessionKeys[peerId] = keyData;
  }

  protected async retrieveIdentityKeySerialized(peerId: string): Promise<Buffer | null> {
    return this.identityKeys[peerId] ?? null;
  }

  protected async retrieveSessionKeyData(peerId: string): Promise<SessionPublicKeyData | null> {
    if (this.fetchError) {
      throw this.fetchError;
    }
    const keyData = this.sessionKeys[peerId];
    return keyData ?? null;
  }

  protected async saveIdentityKeySerialized(keySerialized: Buffer, peerId: string): Promise<void> {
    this.identityKeys[peerId] = keySerialized;
  }

  protected async saveSessionKeyData(keyData: SessionPublicKeyData, peerId: string): Promise<void> {
    if (this.failOnSave) {
      throw new Error('Denied');
    }
    this.sessionKeys[peerId] = keyData;
  }
}

interface MockStoredCertificateData {
  readonly expiryDate: Date;
  readonly serialization: ArrayBuffer;
  readonly issuerId: string;
}

export class MockCertificateStore extends CertificateStore {
  public dataBySubjectId: {
    [nodeId: string]: MockStoredCertificateData[];
  } = {};

  public clear(): void {
    this.dataBySubjectId = {};
  }

  public async forceSave(path: CertificationPath, issuerId: string): Promise<void> {
    await this.saveData(
      path.serialize(),
      await path.leafCertificate.calculateSubjectId(),
      path.leafCertificate.expiryDate,
      issuerId,
    );
  }

  public async deleteExpired(): Promise<void> {
    throw new Error('Not implemented');
  }

  protected async retrieveAllSerializations(
    subjectId: string,
    issuerId: string,
  ): Promise<readonly ArrayBuffer[]> {
    const certificateData = this.dataBySubjectId[subjectId] ?? [];
    const matchingCertificateData = certificateData.filter((d) => d.issuerId === issuerId);
    if (matchingCertificateData.length === 0) {
      return [];
    }
    return matchingCertificateData.map((d) => d.serialization);
  }

  protected async retrieveLatestSerialization(
    subjectId: string,
    issuerId: string,
  ): Promise<ArrayBuffer | null> {
    const certificateData = this.dataBySubjectId[subjectId] ?? [];
    const matchingCertificateData = certificateData.filter((d) => d.issuerId === issuerId);
    if (matchingCertificateData.length === 0) {
      return null;
    }
    const dataSorted = matchingCertificateData.sort(
      (a, b) => b.expiryDate.getTime() - a.expiryDate.getTime(),
    );
    return dataSorted[0].serialization;
  }

  protected async saveData(
    serialization: ArrayBuffer,
    subjectId: string,
    subjectCertificateExpiryDate: Date,
    issuerId: string,
  ): Promise<void> {
    const mockData: MockStoredCertificateData = {
      serialization,
      expiryDate: subjectCertificateExpiryDate,
      issuerId,
    };
    const originalCertificateData = this.dataBySubjectId[subjectId] ?? [];
    this.dataBySubjectId[subjectId] = [...originalCertificateData, mockData];
  }
}

export class MockKeyStoreSet implements KeyStoreSet {
  public readonly certificateStore = new MockCertificateStore();
  public readonly privateKeyStore = new MockPrivateKeyStore();
  public readonly publicKeyStore = new MockPublicKeyStore();

  public clear(): void {
    this.certificateStore.clear();
    this.privateKeyStore.clear();
    this.publicKeyStore.clear();
  }
}
