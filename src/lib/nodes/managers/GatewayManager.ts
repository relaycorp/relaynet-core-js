import { Gateway } from '../Gateway';
import { NodeManager } from './NodeManager';

export class GatewayManager extends NodeManager<Gateway> {
  readonly nodeClass = Gateway;
}
