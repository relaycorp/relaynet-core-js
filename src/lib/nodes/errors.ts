import RelaynetError from '../RelaynetError';

export class NodeError extends RelaynetError {}

export class InvalidPublicNodeConnectionParams extends NodeError {}
