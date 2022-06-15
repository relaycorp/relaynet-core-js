import { PrivateGateway } from '../PrivateGateway';
import { GatewayManager } from './GatewayManager';

export class PrivateGatewayManager extends GatewayManager<PrivateGateway> {
  protected readonly defaultNodeConstructor = PrivateGateway;
}
