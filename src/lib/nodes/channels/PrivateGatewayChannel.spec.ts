import { addDays, setMilliseconds, subMinutes, subSeconds } from 'date-fns';

import {
  derSerializePublicKey,
  generateRSAKeyPair,
  getIdFromIdentityKey,
  getRSAPublicKeyFromPrivate,
} from '../../crypto_wrappers/keys';
import { Certificate } from '../../crypto_wrappers/x509/Certificate';
import { MockKeyStoreSet } from '../../keyStores/testMocks';
import { CertificationPath } from '../../pki/CertificationPath';
import { issueGatewayCertificate } from '../../pki/issuance';
import { NodeCryptoOptions } from '../NodeCryptoOptions';
import { PrivateGatewayChannel } from './PrivateGatewayChannel';

let internetGatewayId: string;
let internetGatewayPublicKey: CryptoKey;
let internetGatewayCertificate: Certificate;
beforeAll(async () => {
  const tomorrow = setMilliseconds(addDays(new Date(), 1), 0);

  // Internet gateway
  const internetGatewayKeyPair = await generateRSAKeyPair();
  internetGatewayPublicKey = internetGatewayKeyPair.publicKey;
  internetGatewayId = await getIdFromIdentityKey(internetGatewayPublicKey);
  internetGatewayCertificate = await issueGatewayCertificate({
    issuerPrivateKey: internetGatewayKeyPair.privateKey,
    subjectPublicKey: internetGatewayPublicKey,
    validityEndDate: tomorrow,
  });
});

const KEY_STORES = new MockKeyStoreSet();
let privateGatewayId: string;
let privateGatewayPrivateKey: CryptoKey;
let privateGatewayPDCCertificate: Certificate;
beforeEach(async () => {
  const { privateKey, publicKey, id } = await KEY_STORES.privateKeyStore.generateIdentityKeyPair();

  // Private gateway
  privateGatewayPrivateKey = privateKey;
  privateGatewayPDCCertificate = await issueGatewayCertificate({
    issuerCertificate: internetGatewayCertificate,
    issuerPrivateKey: privateKey,
    subjectPublicKey: publicKey,
    validityEndDate: internetGatewayCertificate.expiryDate,
  });
  privateGatewayId = id;
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
      subjectPublicKey: await getRSAPublicKeyFromPrivate(privateGatewayPrivateKey),
      issuerPrivateKey: privateGatewayPrivateKey,
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
      await derSerializePublicKey(await getRSAPublicKeyFromPrivate(privateGatewayPrivateKey)),
    );
  });

  test('Certificate should be self-issued', async () => {
    const channel = new StubPrivateGatewayChannel();

    const issuer = await channel.getOrCreateCDAIssuer();

    await expect(issuer.calculateSubjectId()).resolves.toEqual(privateGatewayId);
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
      privateGatewayId,
      privateGatewayId,
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
      issuerPrivateKey: privateGatewayPrivateKey,
      subjectPublicKey: differentSubjectKeyPair.publicKey,
      validityEndDate: privateGatewayPDCCertificate.expiryDate,
    });
    await KEY_STORES.certificateStore.save(
      new CertificationPath(differentSubjectCertificate, []),
      privateGatewayId,
    );
    const channel = new StubPrivateGatewayChannel();

    await expect(channel.getCDAIssuers()).resolves.toHaveLength(0);
  });

  test('Other issuers should be ignored', async () => {
    await KEY_STORES.certificateStore.save(
      new CertificationPath(privateGatewayPDCCertificate, []),
      `not-${privateGatewayId}`,
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
    super(
      privateGatewayPrivateKey,
      privateGatewayPDCCertificate,
      internetGatewayId,
      internetGatewayPublicKey,
      KEY_STORES,
      cryptoOptions,
    );
  }
}
