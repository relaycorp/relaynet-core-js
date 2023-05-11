import { PrivateGateway } from '../PrivateGateway';
import { GatewayManager } from './GatewayManager';

export class PrivateGatewayManager extends GatewayManager<string> {
  protected readonly defaultNodeConstructor = PrivateGateway;
}
