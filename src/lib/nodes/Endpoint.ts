import { ServiceMessage } from '../messages/payloads/ServiceMessage';
import { Node } from './Node';
import { Peer } from './peer';
import { Channel } from './channels/Channel';
import { PrivateEndpointConnParams } from './PrivateEndpointConnParams';
import { InvalidNodeConnectionParams } from './errors';
import { getIdFromIdentityKey } from '../crypto/keys/digest';

export abstract class Endpoint extends Node<ServiceMessage, string> {
  /**
   * Create or update a channel with a private endpoint.
   */
  public async savePrivateEndpointChannel(
    connectionParams: PrivateEndpointConnParams,
  ): Promise<Channel<ServiceMessage, string>> {
    const authSubjectId = await connectionParams.deliveryAuth.leafCertificate.calculateSubjectId();
    if (authSubjectId !== this.id) {
      throw new InvalidNodeConnectionParams(
        `Delivery authorization was granted to another node (${authSubjectId})`,
      );
    }

    const peer: Peer<string> = {
      id: await getIdFromIdentityKey(connectionParams.identityKey),
      internetAddress: connectionParams.internetGatewayAddress,
      identityPublicKey: connectionParams.identityKey,
    };

    await this.keyStores.certificateStore.save(connectionParams.deliveryAuth, peer.id);
    await this.keyStores.publicKeyStore.saveIdentityKey(peer.identityPublicKey);

    await this.keyStores.publicKeyStore.saveSessionKey(
      connectionParams.sessionKey,
      peer.id,
      new Date(),
    );

    return new this.channelConstructor(
      this,
      peer,
      connectionParams.deliveryAuth,
      this.keyStores,
      this.cryptoOptions,
    );
  }
}
