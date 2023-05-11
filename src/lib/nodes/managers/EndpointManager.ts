import { NodeManager } from './NodeManager';
import { PeerInternetAddress } from '../peer';
import { ServiceMessage } from '../../messages/payloads/ServiceMessage';

export abstract class EndpointManager<PeerAddress extends PeerInternetAddress> extends NodeManager<
  ServiceMessage,
  PeerAddress
> {}
