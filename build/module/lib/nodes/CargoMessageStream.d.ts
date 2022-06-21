/// <reference types="node" />
export declare type CargoMessageStream = AsyncIterable<{
    readonly message: Buffer;
    readonly expiryDate: Date;
}>;
