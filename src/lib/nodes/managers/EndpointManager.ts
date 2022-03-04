import ServiceMessage from '../../messages/payloads/ServiceMessage';
import { NodeManager } from './NodeManager';

export class EndpointManager extends NodeManager<ServiceMessage> {}
