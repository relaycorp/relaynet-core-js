import { VError } from 'verror';

export default abstract class RelaynetError extends VError {
  get name(): string {
    return this.constructor.name;
  }
}
