import { Endpoint } from '../Endpoint';
import { NodeManager } from './NodeManager';
export declare class EndpointManager extends NodeManager<Endpoint> {
    protected readonly defaultNodeConstructor: typeof Endpoint;
}
