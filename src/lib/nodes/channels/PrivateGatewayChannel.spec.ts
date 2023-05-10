import { addDays, setMilliseconds, subMinutes, subSeconds } from 'date-fns';

import { generateRSAKeyPair } from '../../crypto/keys/generation';
import { Certificate } from '../../crypto/x509/Certificate';
import { MockKeyStoreSet } from '../../keyStores/testMocks';
import { CertificationPath } from '../../pki/CertificationPath';
import { issueGatewayCertificate } from '../../pki/issuance';
import { NodeCryptoOptions } from '../NodeCryptoOptions';
import { PrivateGatewayChannel } from './PrivateGatewayChannel';
import { derSerializePublicKey } from '../../crypto/keys/serialisation';
import { getIdFromIdentityKey } from '../../crypto/keys/digest';
import { StubGateway } from './_test_utils';
import { Peer } from '../Peer';

let internetGateway: Peer;
let internetGatewayCertificate: Certificate;
beforeAll(async () => {
  const tomorrow = setMilliseconds(addDays(new Date(), 1), 0);

  // Internet gateway
  const internetGatewayKeyPair = await generateRSAKeyPair();
  internetGateway = {
    id: await getIdFromIdentityKey(internetGatewayKeyPair.publicKey),
    identityPublicKey: internetGatewayKeyPair.publicKey,
  };
  internetGatewayCertificate = await issueGatewayCertificate({
    issuerPrivateKey: internetGatewayKeyPair.privateKey,
    subjectPublicKey: internetGatewayKeyPair.publicKey,
    validityEndDate: tomorrow,
  });
});

const KEY_STORES = new MockKeyStoreSet();
let privateGateway: StubGateway;
let privateGatewayPDCCertificate: Certificate;
beforeEach(async () => {
  const { privateKey, publicKey, id } = await KEY_STORES.privateKeyStore.generateIdentityKeyPair();

  // Private gateway
  privateGatewayPDCCertificate = await issueGatewayCertificate({
    issuerCertificate: internetGatewayCertificate,
    issuerPrivateKey: privateKey,
    subjectPublicKey: publicKey,
    validityEndDate: internetGatewayCertificate.expiryDate,
  });
  privateGateway = new StubGateway(id, { privateKey, publicKey }, KEY_STORES, {});
});
afterEach(() => {
  KEY_STORES.clear();
});

describe('getOrCreateCDAIssuer', () => {
  test('Certificate should be generated if none exists', async () => {
    await expect(retrieveCDAIssuer()).resolves.toBeNull();
    const channel = new StubPrivateGatewayChannel();

    const issuer = await channel.getOrCreateCDAIssuer();

    await expect(retrieveCDAIssuer()).resolves.toSatisfy((c) => c.isEqual(issuer));
  });

  test('Certificate be regenerated if latest expires in 90 days', async () => {
    const cutoffDate = addDays(new Date(), 90);
    const expiringIssuer = await issueGatewayCertificate({
      subjectPublicKey: privateGateway.identityKeyPair.publicKey,
      issuerPrivateKey: privateGateway.identityKeyPair.privateKey,
      validityEndDate: subSeconds(cutoffDate, 1),
    });
    await saveCDAIssuer(expiringIssuer);
    const channel = new StubPrivateGatewayChannel();

    const issuer = await channel.getOrCreateCDAIssuer();

    const issuerRetrieved = await retrieveCDAIssuer();
    expect(expiringIssuer.isEqual(issuerRetrieved!)).toBeFalse();
    expect(issuer.isEqual(issuerRetrieved!));
  });

  test('Existing certificate should be reused if it will be valid for 90+ days', async () => {
    const channel = new StubPrivateGatewayChannel();
    const originalIssuer = await channel.getOrCreateCDAIssuer();

    const latestIssuer = await channel.getOrCreateCDAIssuer();

    expect(latestIssuer.isEqual(originalIssuer)).toBeTrue();
  });

  test('Subject key should be that of private gateway', async () => {
    const channel = new StubPrivateGatewayChannel();

    const issuer = await channel.getOrCreateCDAIssuer();

    await expect(derSerializePublicKey(await issuer.getPublicKey())).resolves.toEqual(
      await derSerializePublicKey(privateGateway.identityKeyPair.publicKey),
    );
  });

  test('Certificate should be self-issued', async () => {
    const channel = new StubPrivateGatewayChannel();

    const issuer = await channel.getOrCreateCDAIssuer();

    await expect(issuer.calculateSubjectId()).resolves.toEqual(privateGateway.id);
  });

  test('Certificate should be valid from 90 minutes in the past', async () => {
    const channel = new StubPrivateGatewayChannel();

    const issuer = await channel.getOrCreateCDAIssuer();

    const expectedStartDate = subMinutes(new Date(), 90);
    expect(issuer.startDate).toBeAfter(subSeconds(expectedStartDate, 5));
    expect(issuer.startDate).toBeBefore(expectedStartDate);
  });

  test('Certificate should expire in 180 days when generated', async () => {
    const channel = new StubPrivateGatewayChannel();

    const issuer = await channel.getOrCreateCDAIssuer();

    const expectedExpiryDate = addDays(new Date(), 180);
    expect(issuer.expiryDate).toBeBefore(expectedExpiryDate);
    expect(issuer.expiryDate).toBeAfter(subSeconds(expectedExpiryDate, 5));
  });

  async function retrieveCDAIssuer(): Promise<Certificate | null> {
    const issuerPath = await KEY_STORES.certificateStore.retrieveLatest(
      privateGateway.id,
      privateGateway.id,
    );
    return issuerPath?.leafCertificate ?? null;
  }

  async function saveCDAIssuer(cdaIssuer: Certificate): Promise<void> {
    await KEY_STORES.certificateStore.save(
      new CertificationPath(cdaIssuer, []),
      await cdaIssuer.calculateSubjectId(),
    );
  }
});

describe('getCDAIssuers', () => {
  test('Nothing should be returned if there are no issuers', async () => {
    const channel = new StubPrivateGatewayChannel();

    await expect(channel.getCDAIssuers()).resolves.toHaveLength(0);
  });

  test('Other subjects should be ignored', async () => {
    const differentSubjectKeyPair = await generateRSAKeyPair();
    const differentSubjectCertificate = await issueGatewayCertificate({
      issuerCertificate: privateGatewayPDCCertificate,
      issuerPrivateKey: privateGateway.identityKeyPair.privateKey,
      subjectPublicKey: differentSubjectKeyPair.publicKey,
      validityEndDate: privateGatewayPDCCertificate.expiryDate,
    });
    await KEY_STORES.certificateStore.save(
      new CertificationPath(differentSubjectCertificate, []),
      privateGateway.id,
    );
    const channel = new StubPrivateGatewayChannel();

    await expect(channel.getCDAIssuers()).resolves.toHaveLength(0);
  });

  test('Other issuers should be ignored', async () => {
    await KEY_STORES.certificateStore.save(
      new CertificationPath(privateGatewayPDCCertificate, []),
      `not-${privateGateway.id}`,
    );
    const channel = new StubPrivateGatewayChannel();

    await expect(channel.getCDAIssuers()).resolves.toHaveLength(0);
  });

  test('CDA issuers should be returned', async () => {
    const channel = new StubPrivateGatewayChannel();
    const issuer = await channel.getOrCreateCDAIssuer();

    const issuers = await channel.getCDAIssuers();

    expect(issuers).toHaveLength(1);
    expect(issuers[0].isEqual(issuer)).toBeTrue();
  });
});

class StubPrivateGatewayChannel extends PrivateGatewayChannel {
  constructor(cryptoOptions: Partial<NodeCryptoOptions> = {}) {
    super(privateGateway, privateGatewayPDCCertificate, internetGateway, KEY_STORES, cryptoOptions);
  }
}
