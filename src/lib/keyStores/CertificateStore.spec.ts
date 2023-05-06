import { addSeconds, setMilliseconds, subSeconds } from 'date-fns';
import { expectArrayBuffersToEqual } from '../_test_utils';

import { generateRSAKeyPair, getIdFromIdentityKey } from '../crypto_wrappers/keys';
import { Certificate } from '../crypto_wrappers/x509/Certificate';
import { CertificationPath } from '../pki/CertificationPath';
import { issueGatewayCertificate } from '../pki/issuance';
import { MockCertificateStore } from './testMocks';

const store = new MockCertificateStore();
beforeEach(() => {
  store.clear();
});

let issuerId: string;
let issuerCertificate: Certificate;
let subjectKeyPair: CryptoKeyPair;
let subjectId: string;
let subjectCertificate: Certificate;
let certificationPath: CertificationPath;
beforeAll(async () => {
  const issuerKeyPair = await generateRSAKeyPair();
  issuerId = await getIdFromIdentityKey(issuerKeyPair.publicKey);
  issuerCertificate = await issueGatewayCertificate({
    subjectPublicKey: issuerKeyPair.publicKey,
    issuerPrivateKey: issuerKeyPair.privateKey,
    validityEndDate: addSeconds(new Date(), 10),
  });

  subjectKeyPair = await generateRSAKeyPair();
  subjectId = await getIdFromIdentityKey(subjectKeyPair.publicKey);
  subjectCertificate = await issueGatewayCertificate({
    issuerCertificate,
    issuerPrivateKey: issuerKeyPair.privateKey,
    subjectPublicKey: subjectKeyPair.publicKey,
    validityEndDate: issuerCertificate.expiryDate,
  });

  certificationPath = new CertificationPath(subjectCertificate, [issuerCertificate]);
});

describe('save', () => {
  test('Expired certificate should not be saved', async () => {
    const certificate = await generateSubjectCertificate(subSeconds(new Date(), 1));

    await store.save(new CertificationPath(certificate, [issuerCertificate]), subjectId);

    expect(store.dataBySubjectId).toBeEmpty();
  });

  test('Certification path should be stored', async () => {
    await store.save(certificationPath, issuerId);

    expect(store.dataBySubjectId).toHaveProperty(subjectId);
    const serialization = store.dataBySubjectId[subjectId][0].serialization;
    expectArrayBuffersToEqual(certificationPath.serialize(), serialization);
  });

  test('Expiry date should be taken from certificate', async () => {
    await store.save(certificationPath, issuerId);

    expect(store.dataBySubjectId).toHaveProperty(subjectId);
    expect(store.dataBySubjectId[subjectId][0].expiryDate).toEqual(
      setMilliseconds(subjectCertificate.expiryDate, 0),
    );
  });

  test('Specified issuer id should be honoured', async () => {
    const differentIssuerId = `not-${subjectId}`;

    await store.save(certificationPath, differentIssuerId);

    expect(store.dataBySubjectId).toHaveProperty(subjectId);
    expect(store.dataBySubjectId[subjectId][0].issuerId).toEqual(differentIssuerId);
  });
});

describe('retrieveLatest', () => {
  test('Nothing should be returned if certificate does not exist', async () => {
    await expect(store.retrieveLatest(subjectId, issuerId)).resolves.toBeNull();
  });

  test('Expired certificate should be ignored', async () => {
    const expiredCertificate = await generateSubjectCertificate(subSeconds(new Date(), 1));
    await store.forceSave(new CertificationPath(expiredCertificate, [issuerCertificate]), issuerId);

    await expect(store.retrieveLatest(subjectId, issuerId)).resolves.toBeNull();
  });

  test('Certificates from another issuer should be ignored', async () => {
    await store.save(certificationPath, `not-${issuerId}`);

    await expect(store.retrieveLatest(subjectId, issuerId)).resolves.toBeNull();
  });

  test('Latest path should be returned', async () => {
    const now = new Date();
    const olderCertificate = await generateSubjectCertificate(addSeconds(now, 5));
    await store.save(new CertificationPath(olderCertificate, [issuerCertificate]), issuerId);
    const newerCertificate = await generateSubjectCertificate(addSeconds(now, 10));
    await store.save(new CertificationPath(newerCertificate, [issuerCertificate]), issuerId);

    const path = await store.retrieveLatest(subjectId, issuerId);

    expect(path!.leafCertificate.isEqual(newerCertificate)).toBeTrue();
    expect(path!.certificateAuthorities).toHaveLength(1);
    expect(path!.certificateAuthorities[0].isEqual(issuerCertificate)).toBeTrue();
  });
});

describe('retrieveAll', () => {
  test('Nothing should be returned if no certificate exists', async () => {
    await expect(store.retrieveAll(subjectId, issuerId)).resolves.toBeEmpty();
  });

  test('Expired certificates should be ignored', async () => {
    const validCertificate = await generateSubjectCertificate(addSeconds(new Date(), 3));
    await store.save(new CertificationPath(validCertificate, [issuerCertificate]), issuerId);
    const expiredCertificate = await generateSubjectCertificate(subSeconds(new Date(), 1));
    await store.forceSave(new CertificationPath(expiredCertificate, [issuerCertificate]), issuerId);

    const allPaths = await store.retrieveAll(subjectId, issuerId);

    expect(allPaths).toHaveLength(1);
    expect(validCertificate.isEqual(allPaths[0].leafCertificate)).toBeTrue();
  });

  test('All valid certificates should be returned', async () => {
    const certificate1 = await generateSubjectCertificate(addSeconds(new Date(), 3));
    await store.save(new CertificationPath(certificate1, [issuerCertificate]), issuerId);
    const certificate2 = await generateSubjectCertificate(addSeconds(new Date(), 5));
    await store.save(new CertificationPath(certificate2, [issuerCertificate]), issuerId);

    const allCertificates = await store.retrieveAll(subjectId, issuerId);

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
    await store.save(new CertificationPath(certificate, []), `not-${issuerId}`);

    await expect(store.retrieveAll(subjectId, issuerId)).resolves.toBeEmpty();
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
