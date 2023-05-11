import { NodeManager } from './NodeManager';
import { ServiceMessage } from '../../messages/payloads/ServiceMessage';

export abstract class EndpointManager extends NodeManager<ServiceMessage, string> {}
