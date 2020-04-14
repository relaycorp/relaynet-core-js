import InvalidMessageError from '../InvalidMessageError';
import EmptyPayloadPlaintext from './EmptyPayloadPlaintext';

describe('CargoMessageSet', () => {
  test('serialize() should return an empty buffer', () => {
    const payload = new EmptyPayloadPlaintext();

    expect(payload.serialize()).toHaveProperty('byteLength', 0);
  });

  describe('deserialize', () => {
    test('An empty buffer should be accepted', () => {
      const deserialization = EmptyPayloadPlaintext.deserialize(new ArrayBuffer(0));

      expect(deserialization).toBeInstanceOf(EmptyPayloadPlaintext);
    });

    test('An error should be thrown if buffer is not empty', () => {
      expect(() => EmptyPayloadPlaintext.deserialize(new ArrayBuffer(1))).toThrowError(
        new InvalidMessageError('Payload is not empty'),
      );
    });
  });
});
