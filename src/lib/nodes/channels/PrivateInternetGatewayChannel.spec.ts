import { addDays, addMonths, setMilliseconds, subMinutes } from 'date-fns';

import { arrayBufferFrom, reSerializeCertificate } from '../../_test_utils';
import { PrivateNodeRegistration } from '../../bindings/gsc/PrivateNodeRegistration';
import { PrivateNodeRegistrationAuthorization } from '../../bindings/gsc/PrivateNodeRegistrationAuthorization';

import { generateRSAKeyPair } from '../../crypto/keys/generation';
import { Certificate } from '../../crypto/x509/Certificate';
import { MockKeyStoreSet } from '../../keyStores/testMocks';
import { CargoCollectionAuthorization } from '../../messages/CargoCollectionAuthorization';
import { InvalidMessageError } from '../../messages/InvalidMessageError';
import { Recipient } from '../../messages/Recipient';
import { issueGatewayCertificate } from '../../pki/issuance';
import { SessionKeyPair } from '../../SessionKeyPair';
import { PrivateInternetGatewayChannel } from './PrivateInternetGatewayChannel';
import { derSerializePublicKey } from '../../crypto/keys/serialisation';
import { getIdFromIdentityKey } from '../../crypto/keys/digest';
import { PrivateGateway } from '../PrivateGateway';

let internetGatewayId: string;
let internetGatewayPublicKey: CryptoKey;
let internetGatewayCertificate: Certificate;
let privateGateway: StubPrivateGateway;
let privateGatewayPDCCertificate: Certificate;
beforeAll(async () => {
  const nextYear = setMilliseconds(addDays(new Date(), 360), 0);

  // Internet gateway
  const internetGatewayKeyPair = await generateRSAKeyPair();
  internetGatewayPublicKey = internetGatewayKeyPair.publicKey;
  internetGatewayId = await getIdFromIdentityKey(internetGatewayPublicKey);
  internetGatewayCertificate = await issueGatewayCertificate({
    issuerPrivateKey: internetGatewayKeyPair.privateKey,
    subjectPublicKey: internetGatewayPublicKey,
    validityEndDate: nextYear,
  });

  // Private gateway
  const privateGatewayKeyPair = await generateRSAKeyPair();
  privateGatewayPDCCertificate = reSerializeCertificate(
    await issueGatewayCertificate({
      issuerCertificate: internetGatewayCertificate,
      issuerPrivateKey: internetGatewayKeyPair.privateKey,
      subjectPublicKey: privateGatewayKeyPair.publicKey,
      validityEndDate: nextYear,
    }),
  );
  privateGateway = new StubPrivateGateway(
    await getIdFromIdentityKey(privateGatewayKeyPair.publicKey),
    privateGatewayKeyPair,
    KEY_STORES,
    {},
  );
});

let internetGatewaySessionKeyPair: SessionKeyPair;
beforeAll(async () => {
  internetGatewaySessionKeyPair = await SessionKeyPair.generate();
});

const KEY_STORES = new MockKeyStoreSet();
beforeEach(async () => {
  await KEY_STORES.publicKeyStore.saveIdentityKey(await internetGatewayCertificate.getPublicKey());
  await KEY_STORES.publicKeyStore.saveSessionKey(
    internetGatewaySessionKeyPair.sessionKey,
    internetGatewayId,
    new Date(),
  );
});
afterEach(() => {
  KEY_STORES.clear();
});

const INTERNET_GATEWAY_INTERNET_ADDRESS = 'example.com';

let channel: PrivateInternetGatewayChannel;
beforeEach(() => {
  channel = new PrivateInternetGatewayChannel(
    privateGateway,
    privateGatewayPDCCertificate,
    internetGatewayId,
    internetGatewayPublicKey,
    INTERNET_GATEWAY_INTERNET_ADDRESS,
    KEY_STORES,
    {},
  );
});

test('getOutboundRAMFRecipient should return Internet address of Internet gateway', async () => {
  expect(channel.getOutboundRAMFRecipient()).toEqual<Recipient>({
    id: internetGatewayId,
    internetAddress: INTERNET_GATEWAY_INTERNET_ADDRESS,
  });
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
        privateGateway.identityKeyPair.publicKey,
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
        privateGateway.identityKeyPair.publicKey,
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

    test('Endpoint certificate should be issued by Internet gateway', async () => {
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

    test('Internet gateway Internet gateway should be included in registration', async () => {
      const registrationSerialized = await channel.registerEndpoint(endpointPublicKey);

      const registration = await PrivateNodeRegistration.deserialize(registrationSerialized);

      expect(registration.internetGatewayInternetAddress).toEqual(
        INTERNET_GATEWAY_INTERNET_ADDRESS,
      );
    });

    test('Session key should be absent from registration', async () => {
      const registrationSerialized = await channel.registerEndpoint(endpointPublicKey);

      const registration = await PrivateNodeRegistration.deserialize(registrationSerialized);
      expect(registration.sessionKey).toBeNull();
    });
  });
});

describe('generateCCA', () => {
  test('Recipient should be Internet gateway', async () => {
    const ccaSerialized = await channel.generateCCA();

    const cca = await CargoCollectionAuthorization.deserialize(ccaSerialized);
    expect(cca.recipient).toEqual<Recipient>({
      id: internetGatewayId,
      internetAddress: INTERNET_GATEWAY_INTERNET_ADDRESS,
    });
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
    test('Subject public key should be that of the Internet gateway', async () => {
      const ccaSerialized = await channel.generateCCA();

      const cargoDeliveryAuthorization = await extractCDA(ccaSerialized);
      expect(cargoDeliveryAuthorization.isEqual(internetGatewayCertificate)).toBeFalse();
      await expect(
        derSerializePublicKey(await cargoDeliveryAuthorization.getPublicKey()),
      ).resolves.toEqual(
        await derSerializePublicKey(await internetGatewayCertificate.getPublicKey()),
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
        privateGateway.id,
        privateGateway.id,
      );
      await expect(
        cargoDeliveryAuthorization.getCertificationPath([], [cdaIssuer!.leafCertificate]),
      ).toResolve();
    });

    async function extractCDA(ccaSerialized: ArrayBuffer): Promise<Certificate> {
      const cca = await CargoCollectionAuthorization.deserialize(ccaSerialized);
      const { payload: ccr } = await cca.unwrapPayload(internetGatewaySessionKeyPair.privateKey);
      return ccr.cargoDeliveryAuthorization;
    }
  });
});

class StubPrivateGateway extends PrivateGateway {}
