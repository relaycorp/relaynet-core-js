//region Configure PKI.js
import WebCrypto from 'node-webcrypto-ossl';
import { CryptoEngine, setEngine } from 'pkijs';

const webcrypto = new WebCrypto();
const cryptoEngine = new CryptoEngine({
  crypto: webcrypto,
  name: 'nodeEngine',
  subtle: webcrypto.subtle,
});
setEngine('nodeEngine', webcrypto, cryptoEngine);
//endregion

//region Exports

export { default as RelaynetError } from './lib/RelaynetError';

// PKI
export { default as Certificate } from './lib/crypto_wrappers/x509/Certificate';
export { default as CertificateError } from './lib/crypto_wrappers/x509/CertificateError';
export * from './lib/pki';

// CMS
export { EncryptionOptions } from './lib/crypto_wrappers/cms/envelopedData';
export { SignatureOptions } from './lib/crypto_wrappers/cms/signedData';

// RAMF
export { default as Message } from './lib/ramf/Message';
export { MessageSerializer } from './lib/ramf/MessageSerializer';
export { default as Payload } from './lib/ramf/Payload';
export { default as ServiceMessage } from './lib/ramf/ServiceMessage';
export { default as RAMFError } from './lib/ramf/RAMFError';
export { default as RAMFSyntaxError } from './lib/ramf/RAMFSyntaxError';
export { default as RAMFValidationError } from './lib/ramf/RAMFValidationError';

//endregion
