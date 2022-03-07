import { addDays, setMilliseconds, subMinutes } from 'date-fns';

import {
  derSerializePublicKey,
  generateRSAKeyPair,
  getPrivateAddressFromIdentityKey,
} from '../../crypto_wrappers/keys';
import Certificate from '../../crypto_wrappers/x509/Certificate';
import { MockKeyStoreSet } from '../../keyStores/testMocks';
import { CargoCollectionAuthorization } from '../../messages/CargoCollectionAuthorization';
import { issueGatewayCertificate } from '../../pki';
import { SessionKeyPair } from '../../SessionKeyPair';
import { PrivateGateway } from '../PrivateGateway';
import { PrivatePublicGatewayChannel } from './PrivatePublicGatewayChannel';

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

let publicGatewaySessionKeyPair: SessionKeyPair;
beforeAll(async () => {
  publicGatewaySessionKeyPair = await SessionKeyPair.generate();
});

const KEY_STORES = new MockKeyStoreSet();
beforeEach(async () => {
  await KEY_STORES.publicKeyStore.saveIdentityKey(await publicGatewayCertificate.getPublicKey());
  await KEY_STORES.publicKeyStore.saveSessionKey(
    publicGatewaySessionKeyPair.sessionKey,
    publicGatewayPrivateAddress,
    new Date(),
  );
});
afterEach(() => {
  KEY_STORES.clear();
});

let privateGateway: PrivateGateway;
beforeAll(() => {
  privateGateway = new PrivateGateway(privateGatewayPrivateKey, KEY_STORES);
});

describe('generateCCA', () => {
  const PUBLIC_GATEWAY_PUBLIC_ADDRESS = 'example.com';

  let channel: PrivatePublicGatewayChannel;
  beforeEach(() => {
    channel = new PrivatePublicGatewayChannel(
      privateGateway,
      privateGatewayPrivateKey,
      privateGatewayPDCCertificate,
      publicGatewayPublicKey,
      PUBLIC_GATEWAY_PUBLIC_ADDRESS,
      KEY_STORES,
    );
  });

  test('Recipient should be public gateway', async () => {
    const ccaSerialized = await channel.generateCCA();

    const cca = await CargoCollectionAuthorization.deserialize(ccaSerialized);
    expect(cca.recipientAddress).toEqual(`https://${PUBLIC_GATEWAY_PUBLIC_ADDRESS}`);
  });

  test('Creation date should be 90 minutes in the past to tolerate clock drift', async () => {
    const ccaSerialized = await channel.generateCCA();

    const cca = await CargoCollectionAuthorization.deserialize(ccaSerialized);
    const now = new Date();
    expect(cca.creationDate).toBeBefore(subMinutes(now, 90));
    expect(cca.creationDate).toBeAfter(subMinutes(now, 92));
  });

  test('Expiry date should be 14 days in the future', async () => {
    const ccaSerialized = await channel.generateCCA();

    const cca = await CargoCollectionAuthorization.deserialize(ccaSerialized);
    const now = new Date();
    expect(cca.expiryDate).toBeAfter(addDays(now, 13));
    expect(cca.expiryDate).toBeBefore(addDays(now, 14));
  });

  test('Sender should be PDC certificate of private gateway', async () => {
    const ccaSerialized = await channel.generateCCA();

    const cca = await CargoCollectionAuthorization.deserialize(ccaSerialized);

    expect(cca.senderCertificate.isEqual(privateGatewayPDCCertificate)).toBeTrue();
  });

  test('Sender certificate chain should be empty', async () => {
    const ccaSerialized = await channel.generateCCA();

    const cca = await CargoCollectionAuthorization.deserialize(ccaSerialized);
    expect(cca.senderCaCertificateChain).toEqual([]);
  });

  describe('Cargo Delivery Authorization', () => {
    test('Subject public key should be that of the public gateway', async () => {
      const ccaSerialized = await channel.generateCCA();

      const cargoDeliveryAuthorization = await extractCDA(ccaSerialized);
      expect(cargoDeliveryAuthorization.isEqual(publicGatewayCertificate)).toBeFalse();
      await expect(
        derSerializePublicKey(await cargoDeliveryAuthorization.getPublicKey()),
      ).resolves.toEqual(
        await derSerializePublicKey(await publicGatewayCertificate.getPublicKey()),
      );
    });

    test('Certificate should be valid for 14 days', async () => {
      const ccaSerialized = await channel.generateCCA();

      const cargoDeliveryAuthorization = await extractCDA(ccaSerialized);
      expect(cargoDeliveryAuthorization.expiryDate).toBeAfter(addDays(new Date(), 13));
      expect(cargoDeliveryAuthorization.expiryDate).toBeBefore(addDays(new Date(), 14));
    });

    test('Issuer should be private gateway', async () => {
      const ccaSerialized = await channel.generateCCA();

      const cargoDeliveryAuthorization = await extractCDA(ccaSerialized);
      const cdaIssuer = await KEY_STORES.certificateStore.retrieveLatest(
        privateGatewayPrivateAddress,
        privateGatewayPrivateAddress,
      );
      await expect(cargoDeliveryAuthorization.getCertificationPath([], [cdaIssuer!])).toResolve();
    });

    async function extractCDA(ccaSerialized: ArrayBuffer): Promise<Certificate> {
      const cca = await CargoCollectionAuthorization.deserialize(ccaSerialized);
      const { payload: ccr } = await cca.unwrapPayload(publicGatewaySessionKeyPair.privateKey);
      return ccr.cargoDeliveryAuthorization;
    }
  });
});
