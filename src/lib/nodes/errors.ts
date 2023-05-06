// tslint:disable:max-classes-per-file

import { RelaynetError } from '../RelaynetError';

export class NodeError extends RelaynetError {}

export class InvalidNodeConnectionParams extends NodeError {}
