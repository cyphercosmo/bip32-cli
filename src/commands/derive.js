const chalk = require('chalk');
const { BIP32Factory } = require('bip32');
const ecc = require('tiny-secp256k1');
const { isValidPath, isValidExtendedKey } = require('../utils/validation');
const { formatExtendedKey } = require('../utils/formatting');

// Initialize BIP32 factory with network support
const BIP32 = BIP32Factory(ecc);

function derive(options) {
  try {
    // Validate inputs
    if (!isValidExtendedKey(options.key)) {
      console.error(chalk.red('Error: Invalid extended key format'));
      process.exit(1);
    }

    if (!isValidPath(options.path)) {
      console.error(chalk.red('Error: Invalid derivation path format'));
      process.exit(1);
    }

    // Determine network from key prefix
    const isTestnet = options.key.startsWith('t');
    const network = isTestnet ? {
      wif: 0xef,
      bip32: {
        public: 0x043587cf,
        private: 0x04358394
      }
    } : {
      wif: 0x80,
      bip32: {
        public: 0x0488b21e,
        private: 0x0488ade4
      }
    };

    // Parse the parent key with appropriate network
    const parentNode = BIP32.fromBase58(options.key, network);

    // Derive child key
    const childNode = parentNode.derivePath(options.path);

    // Prepare result
    const result = {
      path: options.path,
      childPrivateKey: childNode.isNeutered() ? null : childNode.toBase58(),
      childPublicKey: childNode.neutered().toBase58(),
      fingerprint: childNode.fingerprint.toString('hex'),
      network: isTestnet ? 'testnet' : 'mainnet'
    };

    if (options.verbose) {
      console.log(chalk.green('\nDerived Keys:'));
      console.log(chalk.yellow('Network:'), result.network);
      console.log(chalk.yellow('Path:'), result.path);
      if (result.childPrivateKey) {
        console.log(formatExtendedKey('Child Private Key', result.childPrivateKey));
      }
      console.log(formatExtendedKey('Child Public Key', result.childPublicKey));
      console.log(chalk.yellow('Fingerprint:'), result.fingerprint);
    } else {
      console.log(result.childPrivateKey || result.childPublicKey);
    }

  } catch (error) {
    console.error(chalk.red('Error deriving keys:'), error.message);
    process.exit(1);
  }
}

module.exports = derive;