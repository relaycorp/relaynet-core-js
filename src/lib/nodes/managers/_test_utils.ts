import { StubNode } from '../_test_utils';
import { NodeManager } from './NodeManager';

export class StubNodeManager extends NodeManager<StubNode> {
  protected readonly defaultNodeConstructor = StubNode;
}
