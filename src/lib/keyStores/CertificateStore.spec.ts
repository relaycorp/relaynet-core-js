import { addSeconds, subSeconds } from 'date-fns';

import { generateRSAKeyPair, getPrivateAddressFromIdentityKey } from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { issueGatewayCertificate } from '../pki';
import { MockCertificateStore } from './testMocks';

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

    await store.save(certificate, privateAddress);

    expect(store.dataByPrivateAddress).toBeEmpty();
  });

  test('Serialization should be stored', async () => {
    const certificate = await generateCertificate(addSeconds(new Date(), 2));

    await store.save(certificate, privateAddress);

    expect(store.dataByPrivateAddress).toHaveProperty(privateAddress);
    expect(store.dataByPrivateAddress[privateAddress][0].certificateSerialized).toEqual(
      certificate.serialize(),
    );
  });

  test('Expiry date should be taken from certificate', async () => {
    const expiryDate = addSeconds(new Date(), 2);
    const certificate = await generateCertificate(expiryDate);

    await store.save(certificate, privateAddress);

    expect(store.dataByPrivateAddress).toHaveProperty(privateAddress);
    expect(store.dataByPrivateAddress[privateAddress][0].expiryDate).toEqual(expiryDate);
  });

  test('Specified issuer private address should be honoured', async () => {
    const certificate = await generateCertificate(addSeconds(new Date(), 2));
    const issuerPrivateAddress = `not-${privateAddress}`;

    await store.save(certificate, issuerPrivateAddress);

    expect(store.dataByPrivateAddress).toHaveProperty(privateAddress);
    expect(store.dataByPrivateAddress[privateAddress][0].issuerPrivateAddress).toEqual(
      issuerPrivateAddress,
    );
  });
});

describe('retrieveLatest', () => {
  test('Nothing should be returned if certificate does not exist', async () => {
    await expect(store.retrieveLatest(privateAddress, privateAddress)).resolves.toBeNull();
  });

  test('Expired certificate should be ignored', async () => {
    const expiredCertificate = await generateCertificate(subSeconds(new Date(), 1));
    await store.forceSave(expiredCertificate);

    await expect(store.retrieveLatest(privateAddress, privateAddress)).resolves.toBeNull();
  });

  test('Latest certificate should be returned', async () => {
    const now = new Date();
    const olderCertificate = await generateCertificate(addSeconds(now, 5));
    await store.forceSave(olderCertificate);
    const newerCertificate = await generateCertificate(addSeconds(now, 10));
    await store.forceSave(newerCertificate);

    const retrievedCertificate = await store.retrieveLatest(privateAddress, privateAddress);

    expect(retrievedCertificate!.isEqual(newerCertificate)).toBeTrue();
  });

  test('Certificates from another issuer should be ignored', async () => {
    const certificate = await generateCertificate(addSeconds(new Date(), 3));
    await store.save(certificate, `not-${privateAddress}`);

    await expect(store.retrieveLatest(privateAddress, privateAddress)).resolves.toBeNull();
  });
});

describe('retrieveAll', () => {
  test('Nothing should be returned if no certificate exists', async () => {
    await expect(store.retrieveAll(privateAddress, privateAddress)).resolves.toBeEmpty();
  });

  test('Expired certificates should be ignored', async () => {
    const validCertificate = await generateCertificate(addSeconds(new Date(), 3));
    await store.forceSave(validCertificate);
    const expiredCertificate = await generateCertificate(subSeconds(new Date(), 1));
    await store.forceSave(expiredCertificate);

    const allCertificates = await store.retrieveAll(privateAddress, privateAddress);

    expect(allCertificates).toHaveLength(1);
    expect(validCertificate.isEqual(allCertificates[0])).toBeTrue();
  });

  test('All valid certificates should be returned', async () => {
    const certificate1 = await generateCertificate(addSeconds(new Date(), 3));
    await store.forceSave(certificate1);
    const certificate2 = await generateCertificate(addSeconds(new Date(), 5));
    await store.forceSave(certificate2);

    const allCertificates = await store.retrieveAll(privateAddress, privateAddress);

    expect(allCertificates).toHaveLength(2);
    expect(allCertificates.filter((c) => certificate1.isEqual(c))).toHaveLength(1);
    expect(allCertificates.filter((c) => certificate2.isEqual(c))).toHaveLength(1);
  });

  test('Certificates from another issuer should be ignored', async () => {
    const certificate = await generateCertificate(addSeconds(new Date(), 3));
    await store.save(certificate, `not-${privateAddress}`);

    await expect(store.retrieveAll(privateAddress, privateAddress)).resolves.toBeEmpty();
  });
});

describe('deleteExpired', () => {
  test('Method should be exposed', async () => {
    await expect(store.deleteExpired()).rejects.toThrowWithMessage(Error, 'Not implemented');
  });
});

async function generateCertificate(validityEndDate: Date): Promise<Certificate> {
  return issueGatewayCertificate({
    issuerPrivateKey: keyPair.privateKey,
    subjectPublicKey: keyPair.publicKey,
    validityEndDate,
    validityStartDate: subSeconds(validityEndDate, 1),
  });
}
