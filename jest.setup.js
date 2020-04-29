const { Crypto } = require('@peculiar/webcrypto');
const { CryptoEngine, setEngine } = require('pkijs');

const crypto = new Crypto();
const cryptoEngine = new CryptoEngine({
  crypto,
  name: 'nodeEngine',
  subtle: crypto.subtle,
});
setEngine('nodeEngine', crypto, cryptoEngine);
