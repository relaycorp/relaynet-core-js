"use strict";
// This module wouldn't duplicate Parcel.ts if TypeScript supported static+abstract members
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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const serialization = __importStar(require("../ramf/serialization"));
const CargoMessageSet_1 = __importDefault(require("./payloads/CargoMessageSet"));
const RAMFMessage_1 = __importDefault(require("./RAMFMessage"));
const concreteMessageTypeOctet = 0x43;
const concreteMessageVersionOctet = 0;
class Cargo extends RAMFMessage_1.default {
    constructor() {
        super(...arguments);
        this.deserializePayload = CargoMessageSet_1.default.deserialize;
    }
    static async deserialize(cargoSerialized) {
        return serialization.deserialize(cargoSerialized, concreteMessageTypeOctet, concreteMessageVersionOctet, Cargo);
    }
    async serialize(senderPrivateKey, signatureOptions) {
        return serialization.serialize(this, concreteMessageTypeOctet, concreteMessageVersionOctet, senderPrivateKey, signatureOptions);
    }
}
exports.default = Cargo;
//# sourceMappingURL=Cargo.js.map