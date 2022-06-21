import { PrivateGateway } from '../PrivateGateway';
import { GatewayManager } from './GatewayManager';
export declare class PrivateGatewayManager extends GatewayManager<PrivateGateway> {
    protected readonly defaultNodeConstructor: typeof PrivateGateway;
}
