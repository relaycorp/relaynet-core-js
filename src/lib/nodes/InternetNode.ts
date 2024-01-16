export interface InternetNode {
  readonly getConnectionParams: () => Promise<Buffer>;
  readonly makeInitialSessionKeyIfMissing: () => Promise<boolean>;
}
