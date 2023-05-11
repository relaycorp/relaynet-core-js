export type PeerInternetAddress = string | undefined;

export interface Peer<Address extends PeerInternetAddress> {
  readonly id: string;

  readonly identityPublicKey: CryptoKey;

  readonly internetAddress: Address;
}
