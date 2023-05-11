import { NodeCryptoOptions } from '../NodeCryptoOptions';
import { KeyStoreSet } from '../../keyStores/KeyStoreSet';
import { Certificate } from '../../crypto/x509/Certificate';
import { Peer, PeerInternetAddress } from '../peer';
import { Channel } from './Channel';
import { Node } from '../Node';
import { PayloadPlaintext } from '../../messages/payloads/PayloadPlaintext';

export type ChannelConstructor<
  Payload extends PayloadPlaintext,
  PeerAddress extends PeerInternetAddress,
> = new (
  node: Node<any, any>,
  peer: Peer<any>,
  deliveryAuth: Certificate,
  keyStores: KeyStoreSet,
  cryptoOptions: Partial<NodeCryptoOptions>,
) => Channel<Payload, PeerAddress>;
