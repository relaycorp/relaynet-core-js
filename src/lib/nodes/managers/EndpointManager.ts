import { Endpoint } from '../Endpoint';
import { NodeManager } from './NodeManager';

export class EndpointManager extends NodeManager<Endpoint> {
  readonly nodeClass = Endpoint;
}
