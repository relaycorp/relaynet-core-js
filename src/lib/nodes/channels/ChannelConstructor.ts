import { NodeCryptoOptions } from '../NodeCryptoOptions';
import { KeyStoreSet } from '../../keyStores/KeyStoreSet';
import { Peer, PeerInternetAddress } from '../peer';
import { Channel } from './Channel';
import { Node } from '../Node';
import { PayloadPlaintext } from '../../messages/payloads/PayloadPlaintext';
import { CertificationPath } from '../../pki/CertificationPath';

export type ChannelConstructor<
  Payload extends PayloadPlaintext,
  PeerAddress extends PeerInternetAddress,
> = new (
  node: Node<any, any>,
  peer: Peer<any>,
  deliveryAuthPath: CertificationPath,
  keyStores: KeyStoreSet,
  cryptoOptions: Partial<NodeCryptoOptions>,
) => Channel<Payload, PeerAddress>;
