import { KeyStoreSet } from '../../keyStores/KeyStoreSet';
import { NodeCryptoOptions } from '../NodeCryptoOptions';
import { Node } from '../Node';
import { PayloadPlaintext } from '../../messages/payloads/PayloadPlaintext';
import { PeerInternetAddress } from '../peer';

export type NodeConstructor<
  Payload extends PayloadPlaintext,
  PeerAddress extends PeerInternetAddress,
> = new (
  id: string,
  identityKeyPair: CryptoKeyPair,
  keyStores: KeyStoreSet,
  cryptoOptions: Partial<NodeCryptoOptions>,
) => Node<Payload, PeerAddress>;
