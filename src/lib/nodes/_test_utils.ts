import { StubPayload } from '../ramf/_test_utils';
import { Node } from './Node';
import { StubNodeChannel } from './channels/_test_utils';

export class StubNode extends Node<StubPayload, undefined> {
  protected readonly channelConstructor = StubNodeChannel;
}
