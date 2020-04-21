import Certificate from '../crypto_wrappers/x509/Certificate';
import { BaseNode, CurrentNodeKeyIds } from './baseNode';

export class Gateway extends BaseNode {
  public async *generateCargoes(
    _messages: AsyncIterableIterator<Buffer>,
    _recipientCertificate: Certificate,
    _currentKeys: CurrentNodeKeyIds,
  ): AsyncIterableIterator<Buffer> {
    throw new Error('Implement!!');
  }
}
