import { addSeconds, setMilliseconds, subSeconds } from 'date-fns';

import { derDeserialize } from '../crypto_wrappers/_utils';
import { generateRSAKeyPair, getPrivateAddressFromIdentityKey } from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { issueGatewayCertificate } from '../pki/issuance';
import { MockCertificateStore } from './testMocks';

const store = new MockCertificateStore();
beforeEach(() => {
  store.clear();
});

let issuerPrivateAddress: string;
let issuerCertificate: Certificate;
let subjectKeyPair: CryptoKeyPair;
let subjectPrivateAddress: string;
let subjectCertificate: Certificate;
beforeAll(async () => {
  const issuerKeyPair = await generateRSAKeyPair();
  issuerPrivateAddress = await getPrivateAddressFromIdentityKey(issuerKeyPair.publicKey);
  issuerCertificate = await issueGatewayCertificate({
    subjectPublicKey: issuerKeyPair.publicKey,
    issuerPrivateKey: issuerKeyPair.privateKey,
    validityEndDate: addSeconds(new Date(), 10),
  });

  subjectKeyPair = await generateRSAKeyPair();
  subjectPrivateAddress = await getPrivateAddressFromIdentityKey(subjectKeyPair.publicKey);
  subjectCertificate = await issueGatewayCertificate({
    issuerCertificate,
    issuerPrivateKey: issuerKeyPair.privateKey,
    subjectPublicKey: subjectKeyPair.publicKey,
    validityEndDate: issuerCertificate.expiryDate,
  });
});

describe('save', () => {
  test('Expired certificate should not be saved', async () => {
    const certificate = await generateSubjectCertificate(subSeconds(new Date(), 1));

    await store.save(certificate, [issuerCertificate], subjectPrivateAddress);

    expect(store.dataByPrivateAddress).toBeEmpty();
  });

  test('Certificate should be stored', async () => {
    await store.save(subjectCertificate, [issuerCertificate], issuerPrivateAddress);

    expect(store.dataByPrivateAddress).toHaveProperty(subjectPrivateAddress);
    const serialization = store.dataByPrivateAddress[subjectPrivateAddress][0].serialization;
    const pathDeserialized = derDeserialize(serialization);
    expect(pathDeserialized.valueBlock.value[0].toBER()).toEqual(subjectCertificate.serialize());
  });

  test('Chain should be stored', async () => {
    await store.save(subjectCertificate, [issuerCertificate], issuerPrivateAddress);

    expect(store.dataByPrivateAddress).toHaveProperty(subjectPrivateAddress);
    const serialization = store.dataByPrivateAddress[subjectPrivateAddress][0].serialization;
    const pathDeserialized = derDeserialize(serialization);
    expect(pathDeserialized.valueBlock.value).toHaveLength(2);
    expect(pathDeserialized.valueBlock.value[1].valueBlock.value).toHaveLength(1);
    const issuerCertificateBlock = pathDeserialized.valueBlock.value[1].valueBlock.value[0];
    expect(issuerCertificateBlock.toBER()).toEqual(issuerCertificate.serialize());
  });

  test('Expiry date should be taken from certificate', async () => {
    await store.save(subjectCertificate, [issuerCertificate], issuerPrivateAddress);

    expect(store.dataByPrivateAddress).toHaveProperty(subjectPrivateAddress);
    expect(store.dataByPrivateAddress[subjectPrivateAddress][0].expiryDate).toEqual(
      setMilliseconds(subjectCertificate.expiryDate, 0),
    );
  });

  test('Specified issuer private address should be honoured', async () => {
    const differentIssuerPrivateAddress = `not-${subjectPrivateAddress}`;

    await store.save(subjectCertificate, [issuerCertificate], differentIssuerPrivateAddress);

    expect(store.dataByPrivateAddress).toHaveProperty(subjectPrivateAddress);
    expect(store.dataByPrivateAddress[subjectPrivateAddress][0].issuerPrivateAddress).toEqual(
      differentIssuerPrivateAddress,
    );
  });
});

describe('retrieveLatest', () => {
  test('Nothing should be returned if certificate does not exist', async () => {
    await expect(
      store.retrieveLatest(subjectPrivateAddress, issuerPrivateAddress),
    ).resolves.toBeNull();
  });

  test('Expired certificate should be ignored', async () => {
    const expiredCertificate = await generateSubjectCertificate(subSeconds(new Date(), 1));
    await store.forceSave(expiredCertificate, [issuerCertificate], issuerPrivateAddress);

    await expect(
      store.retrieveLatest(subjectPrivateAddress, issuerPrivateAddress),
    ).resolves.toBeNull();
  });

  test('Certificates from another issuer should be ignored', async () => {
    await store.save(subjectCertificate, [issuerCertificate], `not-${issuerPrivateAddress}`);

    await expect(
      store.retrieveLatest(subjectPrivateAddress, issuerPrivateAddress),
    ).resolves.toBeNull();
  });

  test('Latest path should be returned', async () => {
    const now = new Date();
    const olderCertificate = await generateSubjectCertificate(addSeconds(now, 5));
    await store.save(olderCertificate, [issuerCertificate], issuerPrivateAddress);
    const newerCertificate = await generateSubjectCertificate(addSeconds(now, 10));
    await store.save(newerCertificate, [issuerCertificate], issuerPrivateAddress);

    const path = await store.retrieveLatest(subjectPrivateAddress, issuerPrivateAddress);

    expect(path!.leafCertificate.isEqual(newerCertificate)).toBeTrue();
    expect(path!.certificateAuthorities).toHaveLength(1);
    expect(path!.certificateAuthorities[0].isEqual(issuerCertificate)).toBeTrue();
  });
});

describe('retrieveAll', () => {
  test('Nothing should be returned if no certificate exists', async () => {
    await expect(
      store.retrieveAll(subjectPrivateAddress, issuerPrivateAddress),
    ).resolves.toBeEmpty();
  });

  test('Expired certificates should be ignored', async () => {
    const validCertificate = await generateSubjectCertificate(addSeconds(new Date(), 3));
    await store.save(validCertificate, [issuerCertificate], issuerPrivateAddress);
    const expiredCertificate = await generateSubjectCertificate(subSeconds(new Date(), 1));
    await store.forceSave(expiredCertificate, [issuerCertificate], issuerPrivateAddress);

    const allPaths = await store.retrieveAll(subjectPrivateAddress, issuerPrivateAddress);

    expect(allPaths).toHaveLength(1);
    expect(validCertificate.isEqual(allPaths[0].leafCertificate)).toBeTrue();
  });

  test('All valid certificates should be returned', async () => {
    const certificate1 = await generateSubjectCertificate(addSeconds(new Date(), 3));
    await store.save(certificate1, [issuerCertificate], issuerPrivateAddress);
    const certificate2 = await generateSubjectCertificate(addSeconds(new Date(), 5));
    await store.save(certificate2, [issuerCertificate], issuerPrivateAddress);

    const allCertificates = await store.retrieveAll(subjectPrivateAddress, issuerPrivateAddress);

    expect(allCertificates).toHaveLength(2);
    expect(allCertificates.filter((p) => certificate1.isEqual(p.leafCertificate))).toHaveLength(1);
    expect(allCertificates.filter((p) => certificate2.isEqual(p.leafCertificate))).toHaveLength(1);
    expect(allCertificates[0].certificateAuthorities).toHaveLength(1);
    expect(allCertificates[0].certificateAuthorities[0].isEqual(issuerCertificate)).toBeTrue();
    expect(allCertificates[1].certificateAuthorities).toHaveLength(1);
    expect(allCertificates[1].certificateAuthorities[0].isEqual(issuerCertificate)).toBeTrue();
  });

  test('Certificates from another issuer should be ignored', async () => {
    const certificate = await generateSubjectCertificate(addSeconds(new Date(), 3));
    await store.save(certificate, [], `not-${issuerPrivateAddress}`);

    await expect(
      store.retrieveAll(subjectPrivateAddress, issuerPrivateAddress),
    ).resolves.toBeEmpty();
  });
});

describe('deleteExpired', () => {
  test('Method should be exposed', async () => {
    await expect(store.deleteExpired()).rejects.toThrowWithMessage(Error, 'Not implemented');
  });
});

async function generateSubjectCertificate(validityEndDate: Date): Promise<Certificate> {
  return issueGatewayCertificate({
    issuerPrivateKey: subjectKeyPair.privateKey,
    subjectPublicKey: subjectKeyPair.publicKey,
    validityEndDate,
    validityStartDate: subSeconds(validityEndDate, 1),
  });
}
