/* tslint:disable:max-classes-per-file */

import { StubPayload } from '../ramf/_test_utils';
import { Node } from './Node';
import { StubNodeChannel } from './channels/_test_utils';
import { Channel } from './channels/Channel';
import { Endpoint } from './Endpoint';

export class StubNode extends Node<StubPayload, undefined> {
  protected readonly channelConstructor = StubNodeChannel;
}

export class StubEndpointChannel extends Channel<StubPayload, string> {}

export class StubEndpoint extends Endpoint {
  protected readonly channelConstructor = StubEndpointChannel;
}
