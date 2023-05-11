/* tslint:disable:max-classes-per-file */

import { Gateway, GatewayPayload } from '../Gateway';
import { Channel } from './Channel';
import { StubPayload } from '../../ramf/_test_utils';

export class StubNodeChannel extends Channel<StubPayload, undefined> {}

class StubGatewayChannel extends Channel<GatewayPayload, undefined> {}

export class StubGateway extends Gateway<undefined> {
  protected readonly channelConstructor = StubGatewayChannel;
}
