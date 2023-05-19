import { MessageOptions, RAMFMessage } from './RAMFMessage';
import { PayloadPlaintext } from './payloads/PayloadPlaintext';
import { Recipient } from './Recipient';
import { Certificate } from '../crypto/x509/Certificate';

export type RAMFMessageConstructor<Payload extends PayloadPlaintext> = new (
  recipient: Recipient,
  senderCertificate: Certificate,
  payloadSerialized: Buffer,
  options?: Partial<MessageOptions>,
) => RAMFMessage<Payload>;
