import { MessageFields } from './MessageSerializer';
import RAMFError from './RAMFError';

export default class RAMFValidationError extends RAMFError {
  constructor(
    message: string,
    readonly invalidMessageFields: MessageFields,
    cause: Error | null = null
  ) {
    super({ cause }, message);
  }
}
