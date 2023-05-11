import { ServiceMessage } from '../messages/payloads/ServiceMessage';
import { Node } from './Node';
import { PeerInternetAddress } from './peer';

export abstract class Endpoint<PeerAddress extends PeerInternetAddress> extends Node<
  ServiceMessage,
  PeerAddress
> {}
