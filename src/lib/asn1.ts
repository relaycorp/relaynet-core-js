import { BaseBlock, Primitive, Sequence } from 'asn1js';

export function makeSequence(...items: ReadonlyArray<BaseBlock<any>>): ArrayBuffer {
  const asn1Items = items.map(
    (item, index) =>
      new Primitive({
        idBlock: { tagClass: 3, tagNumber: index },
        valueHex: item.valueBlock.valueHex,
      } as any),
  );
  return new Sequence({ value: asn1Items } as any).toBER(false);
}
