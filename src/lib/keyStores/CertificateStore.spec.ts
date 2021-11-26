import { addSeconds, subSeconds } from 'date-fns';

import { generateRSAKeyPair, getPrivateAddressFromIdentityKey } from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { issueGatewayCertificate } from '../pki';
import { MockCertificateStore, MockStoredCertificateData } from './testMocks';

const store = new MockCertificateStore();
beforeEach(() => {
  store.clear();
});

let keyPair: CryptoKeyPair;
let privateAddress: string;
beforeAll(async () => {
  keyPair = await generateRSAKeyPair();
  privateAddress = await getPrivateAddressFromIdentityKey(keyPair.publicKey);
});

describe('save', () => {
  test('Expired certificate should not be saved', async () => {
    const certificate = await generateCertificate(subSeconds(new Date(), 1));

    await store.save(certificate);

    expect(store.dataByPrivateAddress).toBeEmpty();
  });

  test('Valid certificate should be saved', async () => {
    const expiryDate = addSeconds(new Date(), 2);
    const certificate = await generateCertificate(expiryDate);

    await store.save(certificate);

    expect(store.dataByPrivateAddress).not.toBeEmpty();
    expect(store.dataByPrivateAddress).toHaveProperty<readonly MockStoredCertificateData[]>(
      privateAddress,
      [{ expiryDate, certificateSerialized: certificate.serialize() }],
    );
  });
});

describe('retrieveLatest', () => {
  test('Nothing should be returned if certificate does not exist', async () => {
    await expect(store.retrieveLatest(privateAddress)).resolves.toBeNull();
  });

  test('Expired certificate should be ignored', async () => {
    const expiredCertificate = await generateCertificate(subSeconds(new Date(), 1));
    await store.forceSave(expiredCertificate);

    await expect(store.retrieveLatest(privateAddress)).resolves.toBeNull();
  });

  test('Valid certificate should be returned', async () => {
    const certificate = await generateCertificate(addSeconds(new Date(), 1));
    await store.save(certificate);

    const retrievedCertificate = await store.retrieveLatest(privateAddress);

    expect(certificate.isEqual(retrievedCertificate!!)).toBeTrue();
  });
});

describe('retrieveAll', () => {
  test.todo('Nothing should be returned if no certificate exists');

  test.todo('Expired certificates should be ignored');

  test.todo('Valid certificates should be returned');
});

describe('deleteExpired', () => {
  test.todo('Backend should be instructed to delete expired certificates');
});

async function generateCertificate(validityEndDate: Date): Promise<Certificate> {
  return issueGatewayCertificate({
    issuerPrivateKey: keyPair.privateKey,
    subjectPublicKey: keyPair.publicKey,
    validityEndDate,
    validityStartDate: subSeconds(validityEndDate, 1),
  });
}
