import { StubNode } from '../_test_utils';
import { NodeManager } from './NodeManager';
import { StubPayload } from '../../ramf/_test_utils';

export class StubNodeManager extends NodeManager<StubPayload, undefined> {
  protected readonly defaultNodeConstructor = StubNode;
}
