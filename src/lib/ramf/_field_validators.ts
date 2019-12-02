import RAMFError from './RAMFError';

const MAX_RECIPIENT_ADDRESS_LENGTH = 2 ** 10 - 1;
const MAX_ID_LENGTH = 2 ** 8 - 1;
const MAX_DATE_TIMESTAMP_SEC = 2 ** 32;
const MAX_DATE_TIMESTAMP_MS = MAX_DATE_TIMESTAMP_SEC * 1_000 - 1;
const MAX_TTL = 2 ** 24 - 1;

export function validateRecipientAddressLength(recipientAddress: string): void {
  if (MAX_RECIPIENT_ADDRESS_LENGTH < Buffer.byteLength(recipientAddress)) {
    throw new RAMFError('Recipient address exceeds maximum length');
  }
}

export function validateMessageIdLength(messageId: string): void {
  if (MAX_ID_LENGTH < messageId.length) {
    throw new RAMFError('Custom id exceeds maximum length');
  }
}

export function validateDate(timestampMs: number): void {
  if (timestampMs < 0) {
    throw new RAMFError('Date cannot be before Unix epoch');
  }
  if (MAX_DATE_TIMESTAMP_MS < timestampMs) {
    throw new RAMFError('Date timestamp cannot be represented with 32 bits');
  }
}

export function validateTtl(ttl: number): void {
  if (ttl < 0) {
    throw new RAMFError('TTL cannot be negative');
  }
  if (MAX_TTL < ttl) {
    throw new RAMFError('TTL must be less than 2^24');
  }
}
