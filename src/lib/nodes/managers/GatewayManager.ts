import { Gateway } from '../Gateway';
import { NodeManager } from './NodeManager';

export abstract class GatewayManager<G extends Gateway> extends NodeManager<G> {}
