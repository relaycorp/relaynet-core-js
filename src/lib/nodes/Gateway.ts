import { CargoCollectionRequest } from '../messages/payloads/CargoCollectionRequest';
import CargoMessageSet from '../messages/payloads/CargoMessageSet';
import { Node } from './Node';

export abstract class Gateway extends Node<CargoMessageSet | CargoCollectionRequest> {}
