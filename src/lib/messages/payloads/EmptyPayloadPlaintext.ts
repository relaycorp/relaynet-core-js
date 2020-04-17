import InvalidMessageError from '../InvalidMessageError';
import PayloadPlaintext from './PayloadPlaintext';

export default class EmptyPayloadPlaintext implements PayloadPlaintext {
  public static deserialize(serialization: ArrayBuffer): EmptyPayloadPlaintext {
    if (serialization.byteLength !== 0) {
      throw new InvalidMessageError('Payload is not empty');
    }
    return new EmptyPayloadPlaintext();
  }

  public serialize(): ArrayBuffer {
    return new ArrayBuffer(0);
  }
}
