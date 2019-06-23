import * as pkijs from 'pkijs';

export function getPkijsCrypto(): SubtleCrypto {
  const cryptoEngine = pkijs.getCrypto();
  if (cryptoEngine === undefined) {
    throw new Error('PKI.js crypto engine is undefined');
  }
  return cryptoEngine;
}
