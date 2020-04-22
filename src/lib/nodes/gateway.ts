import Certificate from '../crypto_wrappers/x509/Certificate';
import { BaseNode } from './baseNode';

export class Gateway extends BaseNode {
  public async *generateCargoes(
    _messages: AsyncIterable<Buffer>,
    _recipientCertificate: Certificate,
    _currentKeyId: Buffer,
  ): AsyncIterable<Buffer> {
    throw new Error('Implement!!');
  }
}
