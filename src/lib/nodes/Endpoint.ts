import { ServiceMessage } from '../messages/payloads/ServiceMessage';
import { Node } from './Node';
import { Peer, PeerInternetAddress } from './peer';
import { Channel } from './channels/Channel';
import { PrivateEndpointConnParams } from './PrivateEndpointConnParams';
import { InvalidNodeConnectionParams } from './errors';
import { getIdFromIdentityKey } from '../crypto/keys/digest';

export abstract class Endpoint<PeerAddress extends PeerInternetAddress> extends Node<
  ServiceMessage,
  PeerAddress
> {
  /**
   * Create or update a channel with a private endpoint.
   */
  public async savePrivateEndpointChannel(
    connectionParams: PrivateEndpointConnParams,
  ): Promise<Channel<ServiceMessage, PeerAddress>> {
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

    if (connectionParams.sessionKey) {
      await this.keyStores.publicKeyStore.saveSessionKey(
        connectionParams.sessionKey,
        peer.id,
        new Date(),
      );
    }

    return new this.channelConstructor(
      this,
      peer,
      connectionParams.deliveryAuth,
      this.keyStores,
      this.cryptoOptions,
    );
  }
}
