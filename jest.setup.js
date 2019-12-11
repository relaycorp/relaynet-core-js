const WebCrypto = require('node-webcrypto-ossl');
const { CryptoEngine, setEngine } = require('pkijs');

const webcrypto = new WebCrypto();
const cryptoEngine = new CryptoEngine({
  crypto: webcrypto,
  name: 'nodeEngine',
  subtle: webcrypto.subtle,
});
setEngine('nodeEngine', webcrypto, cryptoEngine);
