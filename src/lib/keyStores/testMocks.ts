// tslint:disable:max-classes-per-file no-object-mutation readonly-keyword readonly-array

import Certificate from '../crypto_wrappers/x509/Certificate';
import { CertificateStore } from './CertificateStore';
import { KeyStoreSet } from './KeyStoreSet';
import { PrivateKeyStore, SessionPrivateKeyData } from './privateKeyStore';
import { PublicKeyStore, SessionPublicKeyData } from './PublicKeyStore';

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
  public identityKeys: { [peerPrivateAddress: string]: Buffer } = {};

  public sessionKeys: { [key: string]: SessionPublicKeyData } = {};

  constructor(protected readonly failOnSave = false, protected fetchError?: Error) {
    super();
  }

  public clear(): void {
    this.sessionKeys = {};
    this.identityKeys = {};
  }

  public registerSessionKey(keyData: SessionPublicKeyData, peerPrivateAddress: string): void {
    this.sessionKeys[peerPrivateAddress] = keyData;
  }

  protected async retrieveIdentityKeySerialized(
    peerPrivateAddress: string,
  ): Promise<Buffer | null> {
    return this.identityKeys[peerPrivateAddress] ?? null;
  }

  protected async retrieveSessionKeyData(
    peerPrivateAddress: string,
  ): Promise<SessionPublicKeyData | null> {
    if (this.fetchError) {
      throw this.fetchError;
    }
    const keyData = this.sessionKeys[peerPrivateAddress];
    return keyData ?? null;
  }

  protected async saveIdentityKeySerialized(
    keySerialized: Buffer,
    peerPrivateAddress: string,
  ): Promise<void> {
    this.identityKeys[peerPrivateAddress] = keySerialized;
  }

  protected async saveSessionKeyData(
    keyData: SessionPublicKeyData,
    peerPrivateAddress: string,
  ): Promise<void> {
    if (this.failOnSave) {
      throw new Error('Denied');
    }
    this.sessionKeys[peerPrivateAddress] = keyData;
  }
}

interface MockStoredCertificateData {
  readonly expiryDate: Date;
  readonly certificateSerialized: ArrayBuffer;
  readonly issuerPrivateAddress: string;
}

export class MockCertificateStore extends CertificateStore {
  public dataByPrivateAddress: {
    [privateAddress: string]: MockStoredCertificateData[];
  } = {};

  public clear(): void {
    this.dataByPrivateAddress = {};
  }

  public async forceSave(certificate: Certificate, issuerPrivateAddress: string): Promise<void> {
    await this.saveData(
      await certificate.calculateSubjectPrivateAddress(),
      certificate.serialize(),
      certificate.expiryDate,
      issuerPrivateAddress,
    );
  }

  public async deleteExpired(): Promise<void> {
    throw new Error('Not implemented');
  }

  protected async retrieveAllSerializations(
    subjectPrivateAddress: string,
    issuerPrivateAddress: string,
  ): Promise<readonly ArrayBuffer[]> {
    const certificateData = this.dataByPrivateAddress[subjectPrivateAddress] ?? [];
    const matchingCertificateData = certificateData.filter(
      (d) => d.issuerPrivateAddress === issuerPrivateAddress,
    );
    if (matchingCertificateData.length === 0) {
      return [];
    }
    return matchingCertificateData.map((d) => d.certificateSerialized);
  }

  protected async retrieveLatestSerialization(
    subjectPrivateAddress: string,
    issuerPrivateAddress: string,
  ): Promise<ArrayBuffer | null> {
    const certificateData = this.dataByPrivateAddress[subjectPrivateAddress] ?? [];
    const matchingCertificateData = certificateData.filter(
      (d) => d.issuerPrivateAddress === issuerPrivateAddress,
    );
    if (matchingCertificateData.length === 0) {
      return null;
    }
    const dataSorted = matchingCertificateData.sort(
      (a, b) => b.expiryDate.getTime() - a.expiryDate.getTime(),
    );
    return dataSorted[0].certificateSerialized;
  }

  protected async saveData(
    subjectPrivateAddress: string,
    subjectCertificateSerialized: ArrayBuffer,
    subjectCertificateExpiryDate: Date,
    issuerPrivateAddress: string,
  ): Promise<void> {
    const mockData: MockStoredCertificateData = {
      certificateSerialized: subjectCertificateSerialized,
      expiryDate: subjectCertificateExpiryDate,
      issuerPrivateAddress,
    };
    const originalCertificateData = this.dataByPrivateAddress[subjectPrivateAddress] ?? [];
    this.dataByPrivateAddress[subjectPrivateAddress] = [...originalCertificateData, mockData];
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
