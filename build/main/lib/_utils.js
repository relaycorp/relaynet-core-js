"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.makeDateWithSecondPrecision = void 0;
function makeDateWithSecondPrecision(date) {
    const dateWithoutMilliseconds = date ? new Date(date.getTime()) : new Date();
    dateWithoutMilliseconds.setMilliseconds(0);
    return dateWithoutMilliseconds;
}
exports.makeDateWithSecondPrecision = makeDateWithSecondPrecision;
//# sourceMappingURL=_utils.js.map