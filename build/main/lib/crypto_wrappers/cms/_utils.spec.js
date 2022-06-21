"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const pkijs = __importStar(require("pkijs"));
const _utils_1 = require("./_utils");
describe('CMS utils', () => {
    describe('assertPkiType', () => {
        test('correct type', () => {
            const o = new pkijs.Certificate();
            expect(() => {
                (0, _utils_1.assertPkiType)(o, pkijs.Certificate, 'test');
            }).not.toThrow();
        });
        test('incorrect type', () => {
            const o = new pkijs.Certificate();
            expect(() => {
                (0, _utils_1.assertPkiType)(o, pkijs.CertID, 'test');
            }).toThrow(TypeError);
        });
    });
    describe('assertUndefined', () => {
        test('correct', () => {
            const v = false;
            expect(() => {
                (0, _utils_1.assertUndefined)(v, 'test');
            }).not.toThrow();
        });
        test('incorrect', () => {
            const o = undefined;
            expect(() => {
                (0, _utils_1.assertUndefined)(o);
            }).toThrow(Error);
        });
        test('incorrect with param name', () => {
            const o = undefined;
            expect(() => {
                (0, _utils_1.assertUndefined)(o, 'test');
            }).toThrow(Error);
        });
    });
});
//# sourceMappingURL=_utils.spec.js.map