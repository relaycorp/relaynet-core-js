import RAMFSyntaxError from '../ramf/RAMFSyntaxError';
import { describeMessage } from './_test_utils';
import InvalidMessageError from './InvalidMessageError';
import Parcel from './Parcel';
import CargoMessageSet from './payloads/CargoMessageSet';

describe('Parcel', () => {
  describeMessage(Parcel, 0x50, 0x0);

  describe('Additional requirements', () => {
    describe('Deserialization', () => {
      test('Parcels of the largest legal size should be accepted', async () => {
        const parcelSerialized = Buffer.from('a'.repeat(CargoMessageSet.MAX_MESSAGE_LENGTH));

        // Deserialization still fails, but for a different reason:
        await expect(Parcel.deserialize(parcelSerialized)).rejects.toBeInstanceOf(RAMFSyntaxError);
      });

      test('Parcels larger than the maximum legal size should be refused', async () => {
        const parcelSerialized = Buffer.from('a'.repeat(CargoMessageSet.MAX_MESSAGE_LENGTH + 1));

        await expect(Parcel.deserialize(parcelSerialized)).rejects.toEqual(
          new InvalidMessageError(
            `Parcels must not span more than ${CargoMessageSet.MAX_MESSAGE_LENGTH} octets ` +
              `(got ${CargoMessageSet.MAX_MESSAGE_LENGTH + 1} octets)`,
          ),
        );
      });
    });
  });
});
