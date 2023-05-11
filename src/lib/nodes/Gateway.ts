import { Certificate } from '../crypto/x509/Certificate';
import { CargoCollectionRequest } from '../messages/payloads/CargoCollectionRequest';
import { CargoMessageSet } from '../messages/payloads/CargoMessageSet';
import { Node } from './Node';
import { Verifier } from './signatures/Verifier';
import { PeerInternetAddress } from './peer';

export type GatewayPayload = CargoMessageSet | CargoCollectionRequest;

export abstract class Gateway<PeerAddress extends PeerInternetAddress> extends Node<
  GatewayPayload,
  PeerAddress
> {
  public async getGSCVerifier<V extends Verifier>(
    peerId: string,
    verifierClass: new (trustedCertificates: readonly Certificate[]) => V,
  ): Promise<V> {
    const trustedPaths = await this.keyStores.certificateStore.retrieveAll(this.id, peerId);
    return new verifierClass(trustedPaths.map((p) => p.leafCertificate));
  }
}
