import { RelaynetError } from './RelaynetError';

test('.name should be taken from the name of the class', () => {
  class FooError extends RelaynetError {}
  const error = new FooError('Winter is coming');
  expect(error.name).toBe('FooError');
});
