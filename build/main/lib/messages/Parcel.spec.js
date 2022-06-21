"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const RAMFSyntaxError_1 = __importDefault(require("../ramf/RAMFSyntaxError"));
const _test_utils_1 = require("./_test_utils");
const InvalidMessageError_1 = __importDefault(require("./InvalidMessageError"));
const Parcel_1 = __importDefault(require("./Parcel"));
const CargoMessageSet_1 = __importDefault(require("./payloads/CargoMessageSet"));
describe('Parcel', () => {
    (0, _test_utils_1.describeMessage)(Parcel_1.default, 0x50, 0x0);
    describe('Additional requirements', () => {
        describe('Deserialization', () => {
            test('Parcels of the largest legal size should be accepted', async () => {
                const parcelSerialized = Buffer.from('a'.repeat(CargoMessageSet_1.default.MAX_MESSAGE_LENGTH));
                // Deserialization still fails, but for a different reason:
                await expect(Parcel_1.default.deserialize(parcelSerialized)).rejects.toBeInstanceOf(RAMFSyntaxError_1.default);
            });
            test('Parcels larger than the maximum legal size should be refused', async () => {
                const parcelSerialized = Buffer.from('a'.repeat(CargoMessageSet_1.default.MAX_MESSAGE_LENGTH + 1));
                await expect(Parcel_1.default.deserialize(parcelSerialized)).rejects.toEqual(new InvalidMessageError_1.default(`Parcels must not span more than ${CargoMessageSet_1.default.MAX_MESSAGE_LENGTH} octets ` +
                    `(got ${CargoMessageSet_1.default.MAX_MESSAGE_LENGTH + 1} octets)`));
            });
        });
    });
});
//# sourceMappingURL=Parcel.spec.js.map