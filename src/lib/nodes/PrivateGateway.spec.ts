import { addDays, subMinutes, subSeconds } from 'date-fns';

import {
  derSerializePublicKey,
  generateRSAKeyPair,
  getPrivateAddressFromIdentityKey,
  getRSAPublicKeyFromPrivate,
} from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { MockKeyStoreSet } from '../keyStores/testMocks';
import { issueGatewayCertificate } from '../pki';
import { PrivateGateway } from './PrivateGateway';

let privateGatewayPrivateAddress: string;
let privateGatewayPrivateKey: CryptoKey;
beforeAll(async () => {
  const privateGatewayKeyPair = await generateRSAKeyPair();
  privateGatewayPrivateKey = privateGatewayKeyPair.privateKey;
  privateGatewayPrivateAddress = await getPrivateAddressFromIdentityKey(
    privateGatewayKeyPair.publicKey,
  );
});

const KEY_STORES = new MockKeyStoreSet();
beforeEach(async () => {
  await KEY_STORES.privateKeyStore.saveIdentityKey(privateGatewayPrivateKey);
});
afterEach(() => {
  KEY_STORES.clear();
});

describe('getOrCreateCDAIssuer', () => {
  test('Certificate should be generated if none exists', async () => {
    await expect(retrieveCDAIssuer()).resolves.toBeNull();
    const privateGateway = new PrivateGateway(privateGatewayPrivateKey, KEY_STORES);

    const issuer = await privateGateway.getOrCreateCDAIssuer();

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
    const privateGateway = new PrivateGateway(privateGatewayPrivateKey, KEY_STORES);

    const issuer = await privateGateway.getOrCreateCDAIssuer();

    const issuerRetrieved = await retrieveCDAIssuer();
    expect(expiringIssuer.isEqual(issuerRetrieved!)).toBeFalse();
    expect(issuer.isEqual(issuerRetrieved!));
  });

  test('Existing certificate should be reused if it will be valid for 90+ days', async () => {
    const privateGateway = new PrivateGateway(privateGatewayPrivateKey, KEY_STORES);
    const originalIssuer = await privateGateway.getOrCreateCDAIssuer();

    const latestIssuer = await privateGateway.getOrCreateCDAIssuer();

    expect(latestIssuer.isEqual(originalIssuer)).toBeTrue();
  });

  test('Subject key should be that of private gateway', async () => {
    const privateGateway = new PrivateGateway(privateGatewayPrivateKey, KEY_STORES);

    const issuer = await privateGateway.getOrCreateCDAIssuer();

    await expect(derSerializePublicKey(await issuer.getPublicKey())).resolves.toEqual(
      await derSerializePublicKey(await getRSAPublicKeyFromPrivate(privateGatewayPrivateKey)),
    );
  });

  test('Certificate should be self-issued', async () => {
    const privateGateway = new PrivateGateway(privateGatewayPrivateKey, KEY_STORES);

    const issuer = await privateGateway.getOrCreateCDAIssuer();

    await expect(issuer.calculateSubjectPrivateAddress()).resolves.toEqual(
      privateGatewayPrivateAddress,
    );
  });

  test('Certificate should be valid from 90 minutes in the past', async () => {
    const privateGateway = new PrivateGateway(privateGatewayPrivateKey, KEY_STORES);

    const issuer = await privateGateway.getOrCreateCDAIssuer();

    const expectedStartDate = subMinutes(new Date(), 90);
    expect(issuer.startDate).toBeAfter(subSeconds(expectedStartDate, 5));
    expect(issuer.startDate).toBeBefore(expectedStartDate);
  });

  test('Certificate should expire in 180 days when generated', async () => {
    const privateGateway = new PrivateGateway(privateGatewayPrivateKey, KEY_STORES);

    const issuer = await privateGateway.getOrCreateCDAIssuer();

    const expectedExpiryDate = addDays(new Date(), 180);
    expect(issuer.expiryDate).toBeBefore(expectedExpiryDate);
    expect(issuer.expiryDate).toBeAfter(subSeconds(expectedExpiryDate, 5));
  });

  async function retrieveCDAIssuer(): Promise<Certificate | null> {
    return KEY_STORES.certificateStore.retrieveLatest(
      privateGatewayPrivateAddress,
      privateGatewayPrivateAddress,
    );
  }

  async function saveCDAIssuer(cdaIssuer: Certificate): Promise<void> {
    await KEY_STORES.certificateStore.save(
      cdaIssuer,
      await cdaIssuer.calculateSubjectPrivateAddress(),
    );
  }
});
