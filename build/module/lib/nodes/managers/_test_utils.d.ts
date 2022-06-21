import { StubNode } from '../_test_utils';
import { NodeManager } from './NodeManager';
export declare class StubNodeManager extends NodeManager<StubNode> {
    protected readonly defaultNodeConstructor: typeof StubNode;
}
