"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const verror_1 = require("verror");
class RelaynetError extends verror_1.VError {
    get name() {
        return this.constructor.name;
    }
}
exports.default = RelaynetError;
//# sourceMappingURL=RelaynetError.js.map