import RAMFMessage from './RAMFMessage';
interface MessageClass<M extends RAMFMessage<any>> {
    readonly deserialize: (serialization: ArrayBuffer) => Promise<M>;
    new (...args: readonly any[]): M;
}
export declare function describeMessage<M extends RAMFMessage<any>>(messageClass: MessageClass<M>, messageType: number, messageVersion: number): void;
export {};
