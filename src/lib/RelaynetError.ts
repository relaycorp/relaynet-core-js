export default abstract class RelaynetError extends Error {
  get name(): string {
    return this.constructor.name;
  }
}
