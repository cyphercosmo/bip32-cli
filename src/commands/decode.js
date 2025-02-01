const chalk = require('chalk');
const { BIP32Factory } = require('bip32');
const ecc = require('tiny-secp256k1');
const { isValidExtendedKey } = require('../utils/validation');

// Initialize BIP32 factory
const BIP32 = BIP32Factory(ecc);

function decode(options) {
  try {
    const { key } = options;

    // Validate input
    if (!isValidExtendedKey(key)) {
      console.error(chalk.red('Error: Invalid extended key format'));
      process.exit(1);
    }

    // Determine network from key prefix
    const isTestnet = key.startsWith('t');
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

    // Parse the key
    const node = BIP32.fromBase58(key, network);

    // Prepare result
    const result = {
      network: isTestnet ? 'testnet' : 'mainnet',
      depth: node.depth,
      fingerprint: Buffer.from(node.fingerprint).toString('hex'),
      chainCode: node.chainCode.toString('hex'),
      index: node.index,
      parentFingerprint: Buffer.from(node.parentFingerprint).toString('hex'),
      publicKey: node.publicKey.toString('hex'),
      isPrivate: !node.isNeutered()
    };

    if (options.verbose) {
      console.log(chalk.green('\nDecoded Extended Key:'));
      console.log(chalk.yellow('Network:'), result.network);
      console.log(chalk.yellow('Type:'), result.isPrivate ? 'Private' : 'Public');
      console.log(chalk.yellow('Depth:'), result.depth);
      console.log(chalk.yellow('Fingerprint:'), result.fingerprint);
      console.log(chalk.yellow('Parent Fingerprint:'), result.parentFingerprint);
      console.log(chalk.yellow('Index:'), result.index);
      console.log(chalk.yellow('Chain Code:'), result.chainCode);
      console.log(chalk.yellow('Public Key:'), result.publicKey);
    } else {
      console.log(JSON.stringify(result, null, 2));
    }

  } catch (error) {
    console.error(chalk.red('Error decoding key:'), error.message);
    process.exit(1);
  }
}

module.exports = decode;