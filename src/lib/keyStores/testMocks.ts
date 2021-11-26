// tslint:disable:max-classes-per-file no-object-mutation readonly-keyword

import { derSerializePrivateKey } from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { CertificateStore } from './CertificateStore';
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

  public async registerInitialSessionKey(privateKey: CryptoKey, keyId: Buffer): Promise<void> {
    this.keys[keyId.toString('hex')] = {
      keyDer: await derSerializePrivateKey(privateKey),
      type: 'session-initial',
    };
  }

  public async registerSubsequentSessionKey(
    privateKey: CryptoKey,
    keyId: string,
    peerPrivateAddress: string,
  ): Promise<void> {
    this.keys[keyId] = {
      keyDer: await derSerializePrivateKey(privateKey),
      peerPrivateAddress,
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

export interface MockStoredCertificateData {
  readonly expiryDate: Date;
  readonly certificateSerialized: ArrayBuffer;
}

export class MockCertificateStore extends CertificateStore {
  public dataByPrivateAddress: {
    // tslint:disable-next-line:readonly-array
    [privateAddress: string]: MockStoredCertificateData[];
  } = {};

  public expiredCertificatesDeleted: boolean = false;

  public clear(): void {
    this.dataByPrivateAddress = {};
    this.expiredCertificatesDeleted = false;
  }

  public async forceSave(certificate: Certificate): Promise<void> {
    await this.saveData(
      await certificate.calculateSubjectPrivateAddress(),
      certificate.serialize(),
      certificate.expiryDate,
    );
  }

  protected async deleteExpiredData(): Promise<void> {
    this.expiredCertificatesDeleted = true;
  }

  protected async retrieveAllSerializations(
    subjectPrivateAddress: string,
  ): Promise<readonly ArrayBuffer[]> {
    const certificateData = this.dataByPrivateAddress[subjectPrivateAddress];
    if (!certificateData) {
      return [];
    }
    return certificateData.map((d) => d.certificateSerialized);
  }

  protected async retrieveLatestSerialization(
    subjectPrivateAddress: string,
  ): Promise<ArrayBuffer | null> {
    const certificateData = this.dataByPrivateAddress[subjectPrivateAddress] ?? [];
    if (certificateData.length === 0) {
      return null;
    }
    const dataSorted = certificateData.sort(
      (a, b) => a.expiryDate.getDate() - b.expiryDate.getDate(),
    );
    return dataSorted[0].certificateSerialized;
  }

  protected async saveData(
    subjectPrivateAddress: string,
    subjectCertificateSerialized: ArrayBuffer,
    subjectCertificateExpiryDate: Date,
  ): Promise<void> {
    const mockData: MockStoredCertificateData = {
      certificateSerialized: subjectCertificateSerialized,
      expiryDate: subjectCertificateExpiryDate,
    };
    const originalCertificateData = this.dataByPrivateAddress[subjectPrivateAddress] ?? [];
    this.dataByPrivateAddress[subjectPrivateAddress] = [...originalCertificateData, mockData];
  }
}
