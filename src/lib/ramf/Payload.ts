export default abstract class Payload {
  public abstract async serialize(): Promise<Buffer>;
}
