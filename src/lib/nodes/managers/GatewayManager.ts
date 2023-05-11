import { GatewayPayload } from '../Gateway';
import { NodeManager } from './NodeManager';
import { PeerInternetAddress } from '../peer';

export abstract class GatewayManager<PeerAddress extends PeerInternetAddress> extends NodeManager<
  GatewayPayload,
  PeerAddress
> {}
