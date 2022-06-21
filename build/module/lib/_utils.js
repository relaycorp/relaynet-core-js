export function makeDateWithSecondPrecision(date) {
    const dateWithoutMilliseconds = date ? new Date(date.getTime()) : new Date();
    dateWithoutMilliseconds.setMilliseconds(0);
    return dateWithoutMilliseconds;
}
//# sourceMappingURL=_utils.js.map