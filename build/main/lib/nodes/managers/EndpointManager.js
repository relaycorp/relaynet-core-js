"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.EndpointManager = void 0;
const Endpoint_1 = require("../Endpoint");
const NodeManager_1 = require("./NodeManager");
class EndpointManager extends NodeManager_1.NodeManager {
    constructor() {
        super(...arguments);
        this.defaultNodeConstructor = Endpoint_1.Endpoint;
    }
}
exports.EndpointManager = EndpointManager;
//# sourceMappingURL=EndpointManager.js.map