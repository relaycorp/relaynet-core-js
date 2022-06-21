"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PrivateGatewayManager = void 0;
const PrivateGateway_1 = require("../PrivateGateway");
const GatewayManager_1 = require("./GatewayManager");
class PrivateGatewayManager extends GatewayManager_1.GatewayManager {
    constructor() {
        super(...arguments);
        this.defaultNodeConstructor = PrivateGateway_1.PrivateGateway;
    }
}
exports.PrivateGatewayManager = PrivateGatewayManager;
//# sourceMappingURL=PrivateGatewayManager.js.map