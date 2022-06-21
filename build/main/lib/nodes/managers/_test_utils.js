"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.StubNodeManager = void 0;
const _test_utils_1 = require("../_test_utils");
const NodeManager_1 = require("./NodeManager");
class StubNodeManager extends NodeManager_1.NodeManager {
    constructor() {
        super(...arguments);
        this.defaultNodeConstructor = _test_utils_1.StubNode;
    }
}
exports.StubNodeManager = StubNodeManager;
//# sourceMappingURL=_test_utils.js.map