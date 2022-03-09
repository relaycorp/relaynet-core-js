import { addDays, setMilliseconds } from 'date-fns';

import {
  derSerializePublicKey,
  generateRSAKeyPair,
  getPrivateAddressFromIdentityKey,
} from '../crypto_wrappers/keys';
import Certificate from '../crypto_wrappers/x509/Certificate';
import { MockKeyStoreSet } from '../keyStores/testMocks';
import { issueGatewayCertificate } from '../pki';
import { PrivateGateway } from './PrivateGateway';

const PUBLIC_GATEWAY_PUBLIC_ADDRESS = 'example.com';

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
  privateGatewayPrivateAddress = await getPrivateAddressFromIdentityKey(
    privateGatewayKeyPair.publicKey,
  );
  privateGatewayPDCCertificate = await issueGatewayCertificate({
    issuerCertificate: publicGatewayCertificate,
    issuerPrivateKey: publicGatewayKeyPair.privateKey,
    subjectPublicKey: privateGatewayKeyPair.publicKey,
    validityEndDate: tomorrow,
  });
});

const KEY_STORES = new MockKeyStoreSet();
beforeEach(async () => {
  await KEY_STORES.privateKeyStore.saveIdentityKey(privateGatewayPrivateKey);
});
afterEach(() => {
  KEY_STORES.clear();
});

describe('savePublicGatewayChannel', () => {
  test.todo('Delivery authorisation should be stored');

  test.todo('Public key of public gateway should be stored');

  test.todo('Session public key of public gateway should be stored');
});

describe('retrievePublicGatewayChannel', () => {
  test('Null should be returned if public gateway public key is not found', async () => {
    await KEY_STORES.certificateStore.save(
      privateGatewayPDCCertificate,
      publicGatewayPrivateAddress,
    );
    const privateGateway = new PrivateGateway(
      privateGatewayPrivateAddress,
      privateGatewayPrivateKey,
      KEY_STORES,
      {},
    );

    await expect(
      privateGateway.retrievePublicGatewayChannel(
        publicGatewayPrivateAddress,
        PUBLIC_GATEWAY_PUBLIC_ADDRESS,
      ),
    ).resolves.toBeNull();
  });

  test('Null should be returned if delivery authorization is not found', async () => {
    await KEY_STORES.publicKeyStore.saveIdentityKey(publicGatewayPublicKey);
    const privateGateway = new PrivateGateway(
      privateGatewayPrivateAddress,
      privateGatewayPrivateKey,
      KEY_STORES,
      {},
    );

    await expect(
      privateGateway.retrievePublicGatewayChannel(
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
    const privateGateway = new PrivateGateway(
      privateGatewayPrivateAddress,
      privateGatewayPrivateKey,
      KEY_STORES,
      {},
    );

    const channel = await privateGateway.retrievePublicGatewayChannel(
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

  test('Crypto options should be passed', async () => {
    await KEY_STORES.certificateStore.save(
      privateGatewayPDCCertificate,
      publicGatewayPrivateAddress,
    );
    await KEY_STORES.publicKeyStore.saveIdentityKey(publicGatewayPublicKey);
    const cryptoOptions = { encryption: { aesKeySize: 256 } };
    const privateGateway = new PrivateGateway(
      privateGatewayPrivateAddress,
      privateGatewayPrivateKey,
      KEY_STORES,
      cryptoOptions,
    );

    const channel = await privateGateway.retrievePublicGatewayChannel(
      publicGatewayPrivateAddress,
      PUBLIC_GATEWAY_PUBLIC_ADDRESS,
    );

    expect(channel?.cryptoOptions).toEqual(cryptoOptions);
  });
});
