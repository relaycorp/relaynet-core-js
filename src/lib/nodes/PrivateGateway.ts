import { PrivateNodeRegistrationRequest } from '../bindings/gsc/PrivateNodeRegistrationRequest';
import { Certificate } from '../crypto/x509/Certificate';
import { CertificationPath } from '../pki/CertificationPath';
import { SessionKey } from '../SessionKey';
import { PrivateInternetGatewayChannel } from './channels/PrivateInternetGatewayChannel';
import { NodeError } from './errors';
import { Gateway } from './Gateway';

export class PrivateGateway extends Gateway<string> {
  protected readonly channelConstructor = PrivateInternetGatewayChannel;

  /**
   * Produce a `PrivateNodeRegistrationRequest` to register with a Internet gateway.
   *
   * @param authorizationSerialized
   */
  public async requestInternetGatewayRegistration(
    authorizationSerialized: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    const request = new PrivateNodeRegistrationRequest(
      this.identityKeyPair.publicKey,
      authorizationSerialized,
    );
    return request.serialize(this.identityKeyPair.privateKey);
  }

  /**
   * Create channel with Internet gateway using registration details.
   *
   * @param deliveryAuthorization
   * @param internetGatewayIdentityCertificate
   * @param internetGatewaySessionPublicKey
   * @throws NodeError if the `internetGatewayIdentityCertificate` didn't issue
   *    `deliveryAuthorization`
   */
  public async saveInternetGatewayChannel(
    deliveryAuthorization: Certificate,
    internetGatewayIdentityCertificate: Certificate,
    internetGatewaySessionPublicKey: SessionKey,
  ): Promise<void> {
    try {
      await deliveryAuthorization.getCertificationPath([], [internetGatewayIdentityCertificate]);
    } catch (_) {
      throw new NodeError('Delivery authorization was not issued by Internet gateway');
    }

    const internetGatewayId = deliveryAuthorization.getIssuerId()!;
    await this.keyStores.certificateStore.save(
      new CertificationPath(deliveryAuthorization, []),
      internetGatewayId,
    );
    await this.keyStores.publicKeyStore.saveIdentityKey(
      await internetGatewayIdentityCertificate.getPublicKey(),
    );
    await this.keyStores.publicKeyStore.saveSessionKey(
      internetGatewaySessionPublicKey,
      internetGatewayId,
      new Date(),
    );
  }
}
