export class PublicNodeConnectionParams {
  public static deserialize(serialization: ArrayBuffer): PublicNodeConnectionParams {
    throw new Error('implement!' + serialization);
  }

  public serialize(): ArrayBuffer {
    throw new Error('implement');
  }
}
