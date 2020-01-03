import RAMFError from './RAMFError';
import { MessageFields } from './serialization';

export default class RAMFValidationError extends RAMFError {
  constructor(
    message: string,
    readonly invalidMessageFields: MessageFields,
    cause: Error | null = null,
  ) {
    super({ cause }, message);
  }
}
