import { generateRSAKeyPair, getPrivateAddressFromIdentityKey } from '../../crypto_wrappers/keys';
import { MockKeyStoreSet } from '../../keyStores/testMocks';
import { Gateway } from '../Gateway';
import { GatewayManager } from './GatewayManager';

let privateAddress: string;
const KEY_STORES = new MockKeyStoreSet();
beforeEach(async () => {
  const keyPair = await generateRSAKeyPair();
  await KEY_STORES.privateKeyStore.saveIdentityKey(keyPair.privateKey);
  privateAddress = await getPrivateAddressFromIdentityKey(keyPair.privateKey);
});
afterEach(() => {
  KEY_STORES.clear();
});

test('Manager should manage gateways', async () => {
  const manager = new GatewayManager(KEY_STORES);

  await expect(manager.getPrivate(privateAddress)).resolves.toBeInstanceOf(Gateway);
});
