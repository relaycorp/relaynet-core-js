import { Gateway } from './Gateway';

export class PrivateGateway extends Gateway {
  public async generateCCA(
    publicGatewayPrivateAddress: string,
    publicGatewayPublicAddress: string,
  ): Promise<ArrayBuffer> {
    throw new Error('implement' + publicGatewayPrivateAddress + publicGatewayPublicAddress);
  }
}
