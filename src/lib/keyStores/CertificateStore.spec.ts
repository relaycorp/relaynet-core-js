import { addSeconds, subSeconds } from 'date-fns';

import { generateRSAKeyPair } from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { issueGatewayCertificate } from '../pki';
import { MockCertificateStore, MockStoredCertificateData } from './testMocks';

const store = new MockCertificateStore();
beforeEach(() => {
  store.clear();
});

let keyPair: CryptoKeyPair;
beforeAll(async () => {
  keyPair = await generateRSAKeyPair();
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
      await certificate.calculateSubjectPrivateAddress(),
      [{ expiryDate, certificateSerialized: certificate.serialize() }],
    );
  });
});

describe('retrieveLatest', () => {
  test.todo('Nothing should be returned if certificate does not exist');

  test.todo('Expired certificate should be ignored');

  test.todo('Valid certificate should be returned');
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
