import * as pkijs from 'pkijs';

import { assertPkiType, assertUndefined } from './_utils';

describe('CMS utils', () => {
  describe('assertPkiType', () => {
    test('correct type', () => {
      const o = new pkijs.Certificate();

      expect(() => {
        assertPkiType(o, pkijs.Certificate, 'test');
      }).not.toThrow();
    });

    test('incorrect type', () => {
      const o = new pkijs.Certificate();

      expect(() => {
        assertPkiType(o, pkijs.CertID, 'test');
      }).toThrow(TypeError);
    });
  });

  describe('assertUndefined', () => {
    test('correct', () => {
      const v = false;
      expect(() => {
        assertUndefined(v, 'test');
      }).not.toThrow();
    });

    test('incorrect', () => {
      const o = undefined;

      expect(() => {
        assertUndefined(o);
      }).toThrow(Error);
    });

    test('incorrect with param name', () => {
      const o = undefined;

      expect(() => {
        assertUndefined(o, 'test');
      }).toThrow(Error);
    });
  });
});
