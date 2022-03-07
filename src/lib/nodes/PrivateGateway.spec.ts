import { addDays, setMilliseconds, subMinutes, subSeconds } from 'date-fns';

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

let publicGatewayPrivateAddress: string;
let publicGatewayPublicKey: CryptoKey;
let publicGatewayCertificate: Certificate;
let privateGatewayPrivateAddress: string;
let privateGatewayPrivateKey: CryptoKey;
let privateGatewayPDCCertificate: Certificate;
beforeAll(async () => {
  const tomorrow = setMilliseconds(addDays(new Date(), 1), 0);

  // Public gateway
  const publicGatewayKeyPair = await generateRSAKeyPair();
  publicGatewayPublicKey = publicGatewayKeyPair.publicKey;
  publicGatewayPrivateAddress = await getPrivateAddressFromIdentityKey(publicGatewayPublicKey);
  publicGatewayCertificate = await issueGatewayCertificate({
    issuerPrivateKey: publicGatewayKeyPair.privateKey,
    subjectPublicKey: publicGatewayPublicKey,
    validityEndDate: tomorrow,
  });

  // Private gateway
  const privateGatewayKeyPair = await generateRSAKeyPair();
  privateGatewayPrivateKey = privateGatewayKeyPair.privateKey;
  privateGatewayPDCCertificate = await issueGatewayCertificate({
    issuerCertificate: publicGatewayCertificate,
    issuerPrivateKey: publicGatewayKeyPair.privateKey,
    subjectPublicKey: privateGatewayKeyPair.publicKey,
    validityEndDate: tomorrow,
  });
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

describe('getChannelWithPublicGateway', () => {
  const PUBLIC_GATEWAY_PUBLIC_ADDRESS = 'example.com';

  test('Null should be returned if public gateway public key is not found', async () => {
    await KEY_STORES.certificateStore.save(
      privateGatewayPDCCertificate,
      publicGatewayPrivateAddress,
    );
    const privateGateway = new PrivateGateway(privateGatewayPrivateKey, KEY_STORES);

    await expect(
      privateGateway.getChannelWithPublicGateway(
        publicGatewayPrivateAddress,
        PUBLIC_GATEWAY_PUBLIC_ADDRESS,
      ),
    ).resolves.toBeNull();
  });

  test('Null should be returned if delivery authorization is not found', async () => {
    await KEY_STORES.publicKeyStore.saveIdentityKey(publicGatewayPublicKey);
    const privateGateway = new PrivateGateway(privateGatewayPrivateKey, KEY_STORES);

    await expect(
      privateGateway.getChannelWithPublicGateway(
        publicGatewayPrivateAddress,
        PUBLIC_GATEWAY_PUBLIC_ADDRESS,
      ),
    ).resolves.toBeNull();
  });

  test('Channel should be returned if it exists', async () => {
    await KEY_STORES.certificateStore.save(
      privateGatewayPDCCertificate,
      publicGatewayPrivateAddress,
    );
    await KEY_STORES.publicKeyStore.saveIdentityKey(publicGatewayPublicKey);
    const privateGateway = new PrivateGateway(privateGatewayPrivateKey, KEY_STORES);

    const channel = await privateGateway.getChannelWithPublicGateway(
      publicGatewayPrivateAddress,
      PUBLIC_GATEWAY_PUBLIC_ADDRESS,
    );

    expect(channel!.publicGatewayPublicAddress).toEqual(PUBLIC_GATEWAY_PUBLIC_ADDRESS);
    expect(channel!.nodeDeliveryAuth.isEqual(privateGatewayPDCCertificate)).toBeTrue();
    expect(channel!.peerPrivateAddress).toEqual(publicGatewayPrivateAddress);
    await expect(derSerializePublicKey(channel!.peerPublicKey)).resolves.toEqual(
      await derSerializePublicKey(publicGatewayPublicKey),
    );
  });
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
