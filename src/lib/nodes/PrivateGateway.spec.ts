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

const PUBLIC_GATEWAY_INTERNET_ADDRESS = 'example.com';

let publicGatewayId: string;
let publicGatewayPublicKey: CryptoKey;
let publicGatewayCertificate: Certificate;
let privateGatewayId: string;
let privateGatewayPrivateKey: CryptoKey;
let privateGatewayPDCCertificate: Certificate;
beforeAll(async () => {
  const tomorrow = setMilliseconds(addDays(new Date(), 1), 0);

  // Public gateway
  const publicGatewayKeyPair = await generateRSAKeyPair();
  publicGatewayPublicKey = publicGatewayKeyPair.publicKey;
  publicGatewayId = await getIdFromIdentityKey(publicGatewayPublicKey);
  publicGatewayCertificate = reSerializeCertificate(
    await issueGatewayCertificate({
      issuerPrivateKey: publicGatewayKeyPair.privateKey,
      subjectPublicKey: publicGatewayPublicKey,
      validityEndDate: tomorrow,
    }),
  );

  // Private gateway
  const privateGatewayKeyPair = await generateRSAKeyPair();
  privateGatewayPrivateKey = privateGatewayKeyPair.privateKey;
  privateGatewayId = await getIdFromIdentityKey(privateGatewayKeyPair.publicKey);
  privateGatewayPDCCertificate = reSerializeCertificate(
    await issueGatewayCertificate({
      issuerCertificate: publicGatewayCertificate,
      issuerPrivateKey: publicGatewayKeyPair.privateKey,
      subjectPublicKey: privateGatewayKeyPair.publicKey,
      validityEndDate: tomorrow,
    }),
  );
});

const KEY_STORES = new MockKeyStoreSet();
afterEach(() => {
  KEY_STORES.clear();
});

describe('requestPublicGatewayRegistration', () => {
  const AUTHORIZATION_SERIALIZED = arrayBufferFrom('Go ahead');

  test('Registration authorization should be honoured', async () => {
    const privateGateway = new PrivateGateway(
      privateGatewayId,
      privateGatewayPrivateKey,
      KEY_STORES,
      {},
    );

    const requestSerialized = await privateGateway.requestPublicGatewayRegistration(
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

    const requestSerialized = await privateGateway.requestPublicGatewayRegistration(
      AUTHORIZATION_SERIALIZED,
    );

    const request = await PrivateNodeRegistrationRequest.deserialize(requestSerialized);
    await expect(derSerializePublicKey(request.privateNodePublicKey)).resolves.toEqual(
      await derSerializePublicKey(await getRSAPublicKeyFromPrivate(privateGatewayPrivateKey)),
    );
  });
});

describe('savePublicGatewayChannel', () => {
  let publicGatewaySessionPublicKey: SessionKey;
  beforeAll(async () => {
    const publicGatewaySessionKeyPair = await SessionKeyPair.generate();
    publicGatewaySessionPublicKey = publicGatewaySessionKeyPair.sessionKey;
  });

  test('Registration should be refused if public gateway did not issue authorization', async () => {
    const privateGateway = new PrivateGateway(
      privateGatewayId,
      privateGatewayPrivateKey,
      KEY_STORES,
      {},
    );

    await expect(
      privateGateway.savePublicGatewayChannel(
        privateGatewayPDCCertificate,
        privateGatewayPDCCertificate, // Invalid
        publicGatewaySessionPublicKey,
      ),
    ).rejects.toThrowWithMessage(
      NodeError,
      'Delivery authorization was not issued by public gateway',
    );
  });

  test('Delivery authorisation should be stored', async () => {
    const privateGateway = new PrivateGateway(
      privateGatewayId,
      privateGatewayPrivateKey,
      KEY_STORES,
      {},
    );

    await privateGateway.savePublicGatewayChannel(
      privateGatewayPDCCertificate,
      publicGatewayCertificate,
      publicGatewaySessionPublicKey,
    );

    const path = await KEY_STORES.certificateStore.retrieveLatest(
      privateGatewayId,
      publicGatewayId,
    );
    expect(path!.leafCertificate.isEqual(privateGatewayPDCCertificate));
    expect(path!.certificateAuthorities).toHaveLength(0);
  });

  test('Public key of public gateway should be stored', async () => {
    const privateGateway = new PrivateGateway(
      privateGatewayId,
      privateGatewayPrivateKey,
      KEY_STORES,
      {},
    );

    await privateGateway.savePublicGatewayChannel(
      privateGatewayPDCCertificate,
      publicGatewayCertificate,
      publicGatewaySessionPublicKey,
    );

    const publicGatewayPublicKeyRetrieved = await KEY_STORES.publicKeyStore.retrieveIdentityKey(
      publicGatewayId,
    );
    expect(publicGatewayPublicKeyRetrieved).toBeTruthy();
    await expect(derSerializePublicKey(publicGatewayPublicKeyRetrieved!)).resolves.toEqual(
      await derSerializePublicKey(publicGatewayPublicKey),
    );
  });

  test('Session public key of public gateway should be stored', async () => {
    const privateGateway = new PrivateGateway(
      privateGatewayId,
      privateGatewayPrivateKey,
      KEY_STORES,
      {},
    );

    await privateGateway.savePublicGatewayChannel(
      privateGatewayPDCCertificate,
      publicGatewayCertificate,
      publicGatewaySessionPublicKey,
    );

    const keyData = KEY_STORES.publicKeyStore.sessionKeys[publicGatewayId];
    expect(keyData.publicKeyDer).toEqual(
      await derSerializePublicKey(publicGatewaySessionPublicKey.publicKey),
    );
    expect(keyData.publicKeyId).toEqual(publicGatewaySessionPublicKey.keyId);
    expect(keyData.publicKeyCreationTime).toBeBeforeOrEqualTo(new Date());
    expect(keyData.publicKeyCreationTime).toBeAfter(subSeconds(new Date(), 10));
  });
});

describe('retrievePublicGatewayChannel', () => {
  test('Null should be returned if public gateway public key is not found', async () => {
    await KEY_STORES.certificateStore.save(
      new CertificationPath(privateGatewayPDCCertificate, []),
      publicGatewayId,
    );
    const privateGateway = new PrivateGateway(
      privateGatewayId,
      privateGatewayPrivateKey,
      KEY_STORES,
      {},
    );

    await expect(
      privateGateway.retrievePublicGatewayChannel(publicGatewayId, PUBLIC_GATEWAY_INTERNET_ADDRESS),
    ).resolves.toBeNull();
  });

  test('Null should be returned if delivery authorization is not found', async () => {
    await KEY_STORES.publicKeyStore.saveIdentityKey(publicGatewayPublicKey);
    const privateGateway = new PrivateGateway(
      privateGatewayId,
      privateGatewayPrivateKey,
      KEY_STORES,
      {},
    );

    await expect(
      privateGateway.retrievePublicGatewayChannel(publicGatewayId, PUBLIC_GATEWAY_INTERNET_ADDRESS),
    ).resolves.toBeNull();
  });

  test('Channel should be returned if it exists', async () => {
    await KEY_STORES.certificateStore.save(
      new CertificationPath(privateGatewayPDCCertificate, []),
      publicGatewayId,
    );
    await KEY_STORES.publicKeyStore.saveIdentityKey(publicGatewayPublicKey);
    const privateGateway = new PrivateGateway(
      privateGatewayId,
      privateGatewayPrivateKey,
      KEY_STORES,
      {},
    );

    const channel = await privateGateway.retrievePublicGatewayChannel(
      publicGatewayId,
      PUBLIC_GATEWAY_INTERNET_ADDRESS,
    );

    expect(channel!.publicGatewayInternetAddress).toEqual(PUBLIC_GATEWAY_INTERNET_ADDRESS);
    expect(channel!.nodeDeliveryAuth.isEqual(privateGatewayPDCCertificate)).toBeTrue();
    expect(channel!.peerId).toEqual(publicGatewayId);
    await expect(derSerializePublicKey(channel!.peerPublicKey)).resolves.toEqual(
      await derSerializePublicKey(publicGatewayPublicKey),
    );
  });

  test('Crypto options should be passed', async () => {
    await KEY_STORES.certificateStore.save(
      new CertificationPath(privateGatewayPDCCertificate, []),
      publicGatewayId,
    );
    await KEY_STORES.publicKeyStore.saveIdentityKey(publicGatewayPublicKey);
    const cryptoOptions = { encryption: { aesKeySize: 256 } };
    const privateGateway = new PrivateGateway(
      privateGatewayId,
      privateGatewayPrivateKey,
      KEY_STORES,
      cryptoOptions,
    );

    const channel = await privateGateway.retrievePublicGatewayChannel(
      publicGatewayId,
      PUBLIC_GATEWAY_INTERNET_ADDRESS,
    );

    expect(channel?.cryptoOptions).toEqual(cryptoOptions);
  });
});
