import { VError } from 'verror';
export default class RelaynetError extends VError {
    get name() {
        return this.constructor.name;
    }
}
//# sourceMappingURL=RelaynetError.js.map