import Certificate from '../crypto_wrappers/x509/Certificate';
import { CargoCollectionRequest } from '../messages/payloads/CargoCollectionRequest';
import CargoMessageSet from '../messages/payloads/CargoMessageSet';
import { Node } from './Node';
import { Verifier } from './signatures/Verifier';

export abstract class Gateway extends Node<CargoMessageSet | CargoCollectionRequest> {
  public async getGSCVerifier<V extends Verifier>(
    peerPrivateAddress: string,
    verifierClass: new (trustedCertificates: readonly Certificate[]) => V,
  ): Promise<V | null> {
    const trustedCertificates = await this.keyStores.certificateStore.retrieveAll(
      this.privateAddress,
      peerPrivateAddress,
    );
    if (trustedCertificates.length === 0) {
      return null;
    }
    return new verifierClass(trustedCertificates);
  }
}
