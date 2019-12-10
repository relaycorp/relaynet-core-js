import { expectBuffersToEqual } from '../_test_utils';
import { getGroupData, MODPError } from './modp';
import modpGrupsData from './modp-groups.json';

describe('getGroupData', () => {
  test('Data for a supported group should be retrieve successfully', () => {
    const stubGroupDataRaw = modpGrupsData[0];

    const groupData = getGroupData(stubGroupDataRaw.name);

    expectBuffersToEqual(groupData.generator, Buffer.from(stubGroupDataRaw.generator));
    expectBuffersToEqual(groupData.prime, Buffer.from(stubGroupDataRaw.prime));
  });

  test('Requesting an unsupported group should result in an error', () => {
    expect(() => getGroupData('modp5')).toThrowError(
      new MODPError('Unsupported MODP group (modp5)'),
    );
  });
});
