export type CargoMessageStream = AsyncIterable<{
  readonly message: Buffer;
  readonly expiryDate: Date;
}>;
