import { addDays, setMilliseconds, subSeconds } from 'date-fns';

import { arrayBufferFrom, reSerializeCertificate } from '../_test_utils';
import { PrivateNodeRegistrationRequest } from '../bindings/gsc/PrivateNodeRegistrationRequest';
import {
  derSerializePublicKey,
  generateRSAKeyPair,
  getIdFromIdentityKey,
  getRSAPublicKeyFromPrivate,
} from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { MockKeyStoreSet } from '../keyStores/testMocks';
import { CertificationPath } from '../pki/CertificationPath';
import { issueGatewayCertificate } from '../pki/issuance';
import { SessionKey } from '../SessionKey';
import { SessionKeyPair } from '../SessionKeyPair';
import { NodeError } from './errors';
import { PrivateGateway } from './PrivateGateway';

const INTERNET_GATEWAY_INTERNET_ADDRESS = 'example.com';

let internetGatewayId: string;
let internetGatewayPublicKey: CryptoKey;
let internetGatewayCertificate: Certificate;
let privateGatewayId: string;
let privateGatewayPrivateKey: CryptoKey;
let privateGatewayPDCCertificate: Certificate;
beforeAll(async () => {
  const tomorrow = setMilliseconds(addDays(new Date(), 1), 0);

  // Public gateway
  const internetGatewayKeyPair = await generateRSAKeyPair();
  internetGatewayPublicKey = internetGatewayKeyPair.publicKey;
  internetGatewayId = await getIdFromIdentityKey(internetGatewayPublicKey);
  internetGatewayCertificate = reSerializeCertificate(
    await issueGatewayCertificate({
      issuerPrivateKey: internetGatewayKeyPair.privateKey,
      subjectPublicKey: internetGatewayPublicKey,
      validityEndDate: tomorrow,
    }),
  );

  // Private gateway
  const privateGatewayKeyPair = await generateRSAKeyPair();
  privateGatewayPrivateKey = privateGatewayKeyPair.privateKey;
  privateGatewayId = await getIdFromIdentityKey(privateGatewayKeyPair.publicKey);
  privateGatewayPDCCertificate = reSerializeCertificate(
    await issueGatewayCertificate({
      issuerCertificate: internetGatewayCertificate,
      issuerPrivateKey: internetGatewayKeyPair.privateKey,
      subjectPublicKey: privateGatewayKeyPair.publicKey,
      validityEndDate: tomorrow,
    }),
  );
});

const KEY_STORES = new MockKeyStoreSet();
afterEach(() => {
  KEY_STORES.clear();
});

describe('requestInternetGatewayRegistration', () => {
  const AUTHORIZATION_SERIALIZED = arrayBufferFrom('Go ahead');

  test('Registration authorization should be honoured', async () => {
    const privateGateway = new PrivateGateway(
      privateGatewayId,
      privateGatewayPrivateKey,
      KEY_STORES,
      {},
    );

    const requestSerialized = await privateGateway.requestInternetGatewayRegistration(
      AUTHORIZATION_SERIALIZED,
    );

    const request = await PrivateNodeRegistrationRequest.deserialize(requestSerialized);
    expect(request.pnraSerialized).toEqual(AUTHORIZATION_SERIALIZED);
  });

  test('Public key should be honoured', async () => {
    const privateGateway = new PrivateGateway(
      privateGatewayId,
      privateGatewayPrivateKey,
      KEY_STORES,
      {},
    );

    const requestSerialized = await privateGateway.requestInternetGatewayRegistration(
      AUTHORIZATION_SERIALIZED,
    );

    const request = await PrivateNodeRegistrationRequest.deserialize(requestSerialized);
    await expect(derSerializePublicKey(request.privateNodePublicKey)).resolves.toEqual(
      await derSerializePublicKey(await getRSAPublicKeyFromPrivate(privateGatewayPrivateKey)),
    );
  });
});

describe('saveInternetGatewayChannel', () => {
  let internetGatewaySessionPublicKey: SessionKey;
  beforeAll(async () => {
    const internetGatewaySessionKeyPair = await SessionKeyPair.generate();
    internetGatewaySessionPublicKey = internetGatewaySessionKeyPair.sessionKey;
  });

  test('Registration should be refused if Internet gateway did not issue authorization', async () => {
    const privateGateway = new PrivateGateway(
      privateGatewayId,
      privateGatewayPrivateKey,
      KEY_STORES,
      {},
    );

    await expect(
      privateGateway.saveInternetGatewayChannel(
        privateGatewayPDCCertificate,
        privateGatewayPDCCertificate, // Invalid
        internetGatewaySessionPublicKey,
      ),
    ).rejects.toThrowWithMessage(
      NodeError,
      'Delivery authorization was not issued by Internet gateway',
    );
  });

  test('Delivery authorisation should be stored', async () => {
    const privateGateway = new PrivateGateway(
      privateGatewayId,
      privateGatewayPrivateKey,
      KEY_STORES,
      {},
    );

    await privateGateway.saveInternetGatewayChannel(
      privateGatewayPDCCertificate,
      internetGatewayCertificate,
      internetGatewaySessionPublicKey,
    );

    const path = await KEY_STORES.certificateStore.retrieveLatest(
      privateGatewayId,
      internetGatewayId,
    );
    expect(path!.leafCertificate.isEqual(privateGatewayPDCCertificate));
    expect(path!.certificateAuthorities).toHaveLength(0);
  });

  test('Public key of Internet gateway should be stored', async () => {
    const privateGateway = new PrivateGateway(
      privateGatewayId,
      privateGatewayPrivateKey,
      KEY_STORES,
      {},
    );

    await privateGateway.saveInternetGatewayChannel(
      privateGatewayPDCCertificate,
      internetGatewayCertificate,
      internetGatewaySessionPublicKey,
    );

    const internetGatewayPublicKeyRetrieved = await KEY_STORES.publicKeyStore.retrieveIdentityKey(
      internetGatewayId,
    );
    expect(internetGatewayPublicKeyRetrieved).toBeTruthy();
    await expect(derSerializePublicKey(internetGatewayPublicKeyRetrieved!)).resolves.toEqual(
      await derSerializePublicKey(internetGatewayPublicKey),
    );
  });

  test('Session public key of Internet gateway should be stored', async () => {
    const privateGateway = new PrivateGateway(
      privateGatewayId,
      privateGatewayPrivateKey,
      KEY_STORES,
      {},
    );

    await privateGateway.saveInternetGatewayChannel(
      privateGatewayPDCCertificate,
      internetGatewayCertificate,
      internetGatewaySessionPublicKey,
    );

    const keyData = KEY_STORES.publicKeyStore.sessionKeys[internetGatewayId];
    expect(keyData.publicKeyDer).toEqual(
      await derSerializePublicKey(internetGatewaySessionPublicKey.publicKey),
    );
    expect(keyData.publicKeyId).toEqual(internetGatewaySessionPublicKey.keyId);
    expect(keyData.publicKeyCreationTime).toBeBeforeOrEqualTo(new Date());
    expect(keyData.publicKeyCreationTime).toBeAfter(subSeconds(new Date(), 10));
  });
});

describe('retrieveInternetGatewayChannel', () => {
  test('Null should be returned if Internet gateway public key is not found', async () => {
    await KEY_STORES.certificateStore.save(
      new CertificationPath(privateGatewayPDCCertificate, []),
      internetGatewayId,
    );
    const privateGateway = new PrivateGateway(
      privateGatewayId,
      privateGatewayPrivateKey,
      KEY_STORES,
      {},
    );

    await expect(
      privateGateway.retrieveInternetGatewayChannel(
        internetGatewayId,
        INTERNET_GATEWAY_INTERNET_ADDRESS,
      ),
    ).resolves.toBeNull();
  });

  test('Null should be returned if delivery authorization is not found', async () => {
    await KEY_STORES.publicKeyStore.saveIdentityKey(internetGatewayPublicKey);
    const privateGateway = new PrivateGateway(
      privateGatewayId,
      privateGatewayPrivateKey,
      KEY_STORES,
      {},
    );

    await expect(
      privateGateway.retrieveInternetGatewayChannel(
        internetGatewayId,
        INTERNET_GATEWAY_INTERNET_ADDRESS,
      ),
    ).resolves.toBeNull();
  });

  test('Channel should be returned if it exists', async () => {
    await KEY_STORES.certificateStore.save(
      new CertificationPath(privateGatewayPDCCertificate, []),
      internetGatewayId,
    );
    await KEY_STORES.publicKeyStore.saveIdentityKey(internetGatewayPublicKey);
    const privateGateway = new PrivateGateway(
      privateGatewayId,
      privateGatewayPrivateKey,
      KEY_STORES,
      {},
    );

    const channel = await privateGateway.retrieveInternetGatewayChannel(
      internetGatewayId,
      INTERNET_GATEWAY_INTERNET_ADDRESS,
    );

    expect(channel!.internetGatewayInternetAddress).toEqual(INTERNET_GATEWAY_INTERNET_ADDRESS);
    expect(channel!.nodeDeliveryAuth.isEqual(privateGatewayPDCCertificate)).toBeTrue();
    expect(channel!.peerId).toEqual(internetGatewayId);
    await expect(derSerializePublicKey(channel!.peerPublicKey)).resolves.toEqual(
      await derSerializePublicKey(internetGatewayPublicKey),
    );
  });

  test('Crypto options should be passed', async () => {
    await KEY_STORES.certificateStore.save(
      new CertificationPath(privateGatewayPDCCertificate, []),
      internetGatewayId,
    );
    await KEY_STORES.publicKeyStore.saveIdentityKey(internetGatewayPublicKey);
    const cryptoOptions = { encryption: { aesKeySize: 256 } };
    const privateGateway = new PrivateGateway(
      privateGatewayId,
      privateGatewayPrivateKey,
      KEY_STORES,
      cryptoOptions,
    );

    const channel = await privateGateway.retrieveInternetGatewayChannel(
      internetGatewayId,
      INTERNET_GATEWAY_INTERNET_ADDRESS,
    );

    expect(channel?.cryptoOptions).toEqual(cryptoOptions);
  });
});
