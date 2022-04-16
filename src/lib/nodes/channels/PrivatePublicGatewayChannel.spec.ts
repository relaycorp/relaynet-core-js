import { addDays, addMonths, setMilliseconds, subMinutes } from 'date-fns';

import { arrayBufferFrom, reSerializeCertificate } from '../../_test_utils';
import { PrivateNodeRegistration } from '../../bindings/gsc/PrivateNodeRegistration';
import { PrivateNodeRegistrationAuthorization } from '../../bindings/gsc/PrivateNodeRegistrationAuthorization';

import {
  derSerializePublicKey,
  generateRSAKeyPair,
  getPrivateAddressFromIdentityKey,
} from '../../crypto_wrappers/keys';
import Certificate from '../../crypto_wrappers/x509/Certificate';
import { MockKeyStoreSet } from '../../keyStores/testMocks';
import { CargoCollectionAuthorization } from '../../messages/CargoCollectionAuthorization';
import InvalidMessageError from '../../messages/InvalidMessageError';
import { issueGatewayCertificate } from '../../pki/issuance';
import { SessionKeyPair } from '../../SessionKeyPair';
import { PrivatePublicGatewayChannel } from './PrivatePublicGatewayChannel';

let publicGatewayPrivateAddress: string;
let publicGatewayPublicKey: CryptoKey;
let publicGatewayCertificate: Certificate;
let privateGatewayPrivateAddress: string;
let privateGatewayKeyPair: CryptoKeyPair;
let privateGatewayPDCCertificate: Certificate;
beforeAll(async () => {
  const nextYear = setMilliseconds(addDays(new Date(), 360), 0);

  // Public gateway
  const publicGatewayKeyPair = await generateRSAKeyPair();
  publicGatewayPublicKey = publicGatewayKeyPair.publicKey;
  publicGatewayPrivateAddress = await getPrivateAddressFromIdentityKey(publicGatewayPublicKey);
  publicGatewayCertificate = await issueGatewayCertificate({
    issuerPrivateKey: publicGatewayKeyPair.privateKey,
    subjectPublicKey: publicGatewayPublicKey,
    validityEndDate: nextYear,
  });

  // Private gateway
  privateGatewayKeyPair = await generateRSAKeyPair();
  privateGatewayPDCCertificate = reSerializeCertificate(
    await issueGatewayCertificate({
      issuerCertificate: publicGatewayCertificate,
      issuerPrivateKey: publicGatewayKeyPair.privateKey,
      subjectPublicKey: privateGatewayKeyPair.publicKey,
      validityEndDate: nextYear,
    }),
  );
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

const PUBLIC_GATEWAY_PUBLIC_ADDRESS = 'example.com';

let channel: PrivatePublicGatewayChannel;
beforeEach(() => {
  channel = new PrivatePublicGatewayChannel(
    privateGatewayKeyPair.privateKey!,
    privateGatewayPDCCertificate,
    publicGatewayPrivateAddress,
    publicGatewayPublicKey,
    PUBLIC_GATEWAY_PUBLIC_ADDRESS,
    KEY_STORES,
    {},
  );
});

test('getOutboundRAMFAddress should return public address of public gateway', () => {
  expect(channel.getOutboundRAMFAddress()).toEqual(`https://${PUBLIC_GATEWAY_PUBLIC_ADDRESS}`);
});

describe('Endpoint registration', () => {
  const GATEWAY_DATA = arrayBufferFrom('the gw data');
  const EXPIRY_DATE = setMilliseconds(addDays(new Date(), 1), 0);

  describe('authorizeEndpointRegistration', () => {
    test('Gateway data should be honoured', async () => {
      const authorizationSerialized = await channel.authorizeEndpointRegistration(
        GATEWAY_DATA,
        EXPIRY_DATE,
      );

      const authorization = await PrivateNodeRegistrationAuthorization.deserialize(
        authorizationSerialized,
        privateGatewayKeyPair.publicKey,
      );
      expect(authorization.gatewayData).toEqual(GATEWAY_DATA);
    });

    test('Expiry date should be honoured', async () => {
      const authorizationSerialized = await channel.authorizeEndpointRegistration(
        GATEWAY_DATA,
        EXPIRY_DATE,
      );

      const authorization = await PrivateNodeRegistrationAuthorization.deserialize(
        authorizationSerialized,
        privateGatewayKeyPair.publicKey,
      );
      expect(authorization.expiryDate).toEqual(EXPIRY_DATE);
    });
  });

  describe('verifyEndpointRegistrationAuthorization', () => {
    test('Error should be thrown if authorization is invalid', async () => {
      const authorization = new PrivateNodeRegistrationAuthorization(EXPIRY_DATE, GATEWAY_DATA);
      const differentKeyPair = await generateRSAKeyPair();
      const authorizationSerialized = await authorization.serialize(
        differentKeyPair.privateKey, // Wrong key
      );

      await expect(
        channel.verifyEndpointRegistrationAuthorization(authorizationSerialized),
      ).rejects.toBeInstanceOf(InvalidMessageError);
    });

    test('Gateway data should be returned if signed with right key', async () => {
      const authorizationSerialized = await channel.authorizeEndpointRegistration(
        GATEWAY_DATA,
        EXPIRY_DATE,
      );

      await expect(
        channel.verifyEndpointRegistrationAuthorization(authorizationSerialized),
      ).resolves.toEqual(GATEWAY_DATA);
    });
  });

  describe('registerEndpoint', () => {
    let endpointPublicKey: CryptoKey;
    beforeAll(async () => {
      const endpointKeyPair = await generateRSAKeyPair();
      endpointPublicKey = endpointKeyPair.publicKey;
    });

    test('Endpoint certificate should be issued by public gateway', async () => {
      const registrationSerialized = await channel.registerEndpoint(endpointPublicKey);

      const registration = await PrivateNodeRegistration.deserialize(registrationSerialized);
      const endpointCertificate = reSerializeCertificate(registration.privateNodeCertificate);
      await expect(
        endpointCertificate.getCertificationPath([], [privateGatewayPDCCertificate]),
      ).resolves.toHaveLength(2);
    });

    test('Endpoint certificate should be valid starting now', async () => {
      const preRegistrationDate = setMilliseconds(new Date(), 0);

      const registrationSerialized = await channel.registerEndpoint(endpointPublicKey);

      const registration = await PrivateNodeRegistration.deserialize(registrationSerialized);
      expect(registration.privateNodeCertificate.startDate).toBeAfterOrEqualTo(preRegistrationDate);
      expect(registration.privateNodeCertificate.startDate).toBeBeforeOrEqualTo(new Date());
    });

    test('Endpoint certificate should be valid for 6 months', async () => {
      const preRegistrationDate = setMilliseconds(new Date(), 0);

      const registrationSerialized = await channel.registerEndpoint(endpointPublicKey);

      const registration = await PrivateNodeRegistration.deserialize(registrationSerialized);
      expect(registration.privateNodeCertificate.expiryDate).toBeAfterOrEqualTo(
        addMonths(preRegistrationDate, 6),
      );
      expect(registration.privateNodeCertificate.expiryDate).toBeBeforeOrEqualTo(
        addMonths(new Date(), 6),
      );
    });

    test('Endpoint certificate should honor subject public key', async () => {
      const registrationSerialized = await channel.registerEndpoint(endpointPublicKey);

      const registration = await PrivateNodeRegistration.deserialize(registrationSerialized);
      await expect(
        derSerializePublicKey(await registration.privateNodeCertificate.getPublicKey()),
      ).resolves.toEqual(await derSerializePublicKey(endpointPublicKey));
    });

    test('Gateway certificate should be included in registration', async () => {
      const registrationSerialized = await channel.registerEndpoint(endpointPublicKey);

      const registration = await PrivateNodeRegistration.deserialize(registrationSerialized);
      expect(registration.gatewayCertificate.isEqual(privateGatewayPDCCertificate)).toBeTrue();
    });

    test('Session key should be absent from registration', async () => {
      const registrationSerialized = await channel.registerEndpoint(endpointPublicKey);

      const registration = await PrivateNodeRegistration.deserialize(registrationSerialized);
      expect(registration.sessionKey).toBeNull();
    });
  });
});

describe('generateCCA', () => {
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
      await expect(
        cargoDeliveryAuthorization.getCertificationPath([], [cdaIssuer!.leafCertificate]),
      ).toResolve();
    });

    async function extractCDA(ccaSerialized: ArrayBuffer): Promise<Certificate> {
      const cca = await CargoCollectionAuthorization.deserialize(ccaSerialized);
      const { payload: ccr } = await cca.unwrapPayload(publicGatewaySessionKeyPair.privateKey);
      return ccr.cargoDeliveryAuthorization;
    }
  });
});
