import { VError } from 'verror';

export abstract class RelaynetError extends VError {
  override get name(): string {
    return this.constructor.name;
  }
}
