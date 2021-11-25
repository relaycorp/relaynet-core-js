import { MockCertificateStore } from './testMocks';

const store = new MockCertificateStore();
beforeEach(() => {
  store.clear();
});

describe('save', () => {
  test.todo('Expired certificate should not be saved');

  test.todo('Valid certificate should be saved');
});

describe('retrieveLatest', () => {
  test.todo('Nothing should be returned if certificate does not exist');

  test.todo('Expired certificate should be ignored');

  test.todo('Valid certificate should be returned');
});

describe('retrieveAll', () => {
  test.todo('Nothing should be returned if no certificate exists');

  test.todo('Expired certificates should be ignored');

  test.todo('Valid certificates should be returned');
});

describe('deleteExpired', () => {
  test.todo('Backend should be instructed to delete expired certificates');
});
