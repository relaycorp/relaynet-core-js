import ServiceMessage from '../messages/payloads/ServiceMessage';
import { Node } from './Node';

export class Endpoint extends Node<ServiceMessage> {}
