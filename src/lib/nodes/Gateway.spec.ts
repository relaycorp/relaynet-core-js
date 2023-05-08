import { addDays, setMilliseconds } from 'date-fns';

import { reSerializeCertificate } from '../_test_utils';
import { generateRSAKeyPair } from '../crypto/keys/generation';
import { Certificate } from '../crypto/x509/Certificate';
import { MockKeyStoreSet } from '../keyStores/testMocks';
import { CertificationPath } from '../pki/CertificationPath';
import { issueGatewayCertificate } from '../pki/issuance';
import { Gateway } from './Gateway';
import { StubVerifier } from './signatures/_test_utils';
import { getIdFromIdentityKey } from '../crypto/keys/digest';

let nodeId: string;
let nodeKeyPair: CryptoKeyPair;
let nodeCertificate: Certificate;
let nodeCertificateIssuer: Certificate;
let nodeCertificateIssuerId: string;
beforeAll(async () => {
  const tomorrow = setMilliseconds(addDays(new Date(), 1), 0);

  const issuerKeyPair = await generateRSAKeyPair();
  nodeCertificateIssuer = reSerializeCertificate(
    await issueGatewayCertificate({
      issuerPrivateKey: issuerKeyPair.privateKey,
      subjectPublicKey: issuerKeyPair.publicKey,
      validityEndDate: tomorrow,
    }),
  );
  nodeCertificateIssuerId = await nodeCertificateIssuer.calculateSubjectId();

  nodeKeyPair = await generateRSAKeyPair();
  nodeCertificate = reSerializeCertificate(
    await issueGatewayCertificate({
      issuerCertificate: nodeCertificateIssuer,
      issuerPrivateKey: issuerKeyPair.privateKey,
      subjectPublicKey: nodeKeyPair.publicKey,
      validityEndDate: tomorrow,
    }),
  );
  nodeId = await getIdFromIdentityKey(nodeKeyPair.publicKey);
});

const KEY_STORES = new MockKeyStoreSet();
beforeEach(async () => {
  KEY_STORES.clear();
});

describe('getGSCVerifier', () => {
  test('Certificates from a different issuer should be ignored', async () => {
    const gateway = new StubGateway(nodeId, nodeKeyPair, KEY_STORES, {});
    await KEY_STORES.certificateStore.save(
      new CertificationPath(nodeCertificate, []),
      nodeCertificateIssuerId,
    );

    const verifier = await gateway.getGSCVerifier(`not-${nodeCertificateIssuerId}`, StubVerifier);

    expect(verifier.getTrustedCertificates()).toBeEmpty();
  });

  test('All certificates should be set as trusted', async () => {
    const gateway = new StubGateway(nodeId, nodeKeyPair, KEY_STORES, {});
    await KEY_STORES.certificateStore.save(
      new CertificationPath(nodeCertificate, []),
      nodeCertificateIssuerId,
    );

    const verifier = await gateway.getGSCVerifier(nodeCertificateIssuerId, StubVerifier);

    const trustedCertificates = verifier!.getTrustedCertificates();
    expect(trustedCertificates).toHaveLength(1);
    expect(nodeCertificate.isEqual(trustedCertificates[0])).toBeTrue();
  });
});

class StubGateway extends Gateway {}
