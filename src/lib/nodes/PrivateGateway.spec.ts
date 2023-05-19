import { addDays, setMilliseconds, subSeconds } from 'date-fns';

import { arrayBufferFrom, reSerializeCertificate } from '../_test_utils';
import { PrivateNodeRegistrationRequest } from '../bindings/gsc/PrivateNodeRegistrationRequest';
import { generateRSAKeyPair } from '../crypto/keys/generation';
import { Certificate } from '../crypto/x509/Certificate';
import { MockKeyStoreSet } from '../keyStores/testMocks';
import { issueGatewayCertificate } from '../pki/issuance';
import { SessionKey } from '../SessionKey';
import { SessionKeyPair } from '../SessionKeyPair';
import { NodeError } from './errors';
import { PrivateGateway } from './PrivateGateway';
import { derSerializePublicKey } from '../crypto/keys/serialisation';
import { getIdFromIdentityKey } from '../crypto/keys/digest';

let internetGatewayId: string;
let internetGatewayPublicKey: CryptoKey;
let internetGatewayCertificate: Certificate;
let privateGatewayId: string;
let privateGatewayIdKeyPair: CryptoKeyPair;
let privateGatewayPDCCertificate: Certificate;
beforeAll(async () => {
  const tomorrow = setMilliseconds(addDays(new Date(), 1), 0);

  // Internet gateway
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
  privateGatewayIdKeyPair = await generateRSAKeyPair();
  privateGatewayId = await getIdFromIdentityKey(privateGatewayIdKeyPair.publicKey);
  privateGatewayPDCCertificate = reSerializeCertificate(
    await issueGatewayCertificate({
      issuerCertificate: internetGatewayCertificate,
      issuerPrivateKey: internetGatewayKeyPair.privateKey,
      subjectPublicKey: privateGatewayIdKeyPair.publicKey,
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
      privateGatewayIdKeyPair,
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
      privateGatewayIdKeyPair,
      KEY_STORES,
      {},
    );

    const requestSerialized = await privateGateway.requestInternetGatewayRegistration(
      AUTHORIZATION_SERIALIZED,
    );

    const request = await PrivateNodeRegistrationRequest.deserialize(requestSerialized);
    await expect(derSerializePublicKey(request.privateNodePublicKey)).resolves.toEqual(
      await derSerializePublicKey(privateGatewayIdKeyPair.publicKey),
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
      privateGatewayIdKeyPair,
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
      privateGatewayIdKeyPair,
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
      privateGatewayIdKeyPair,
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
      privateGatewayIdKeyPair,
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
