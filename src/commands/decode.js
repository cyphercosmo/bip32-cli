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

    // Format buffers to hex strings
    const fingerprint = node.fingerprint ? node.fingerprint.toString('hex').padStart(8, '0') : '00000000';
    const parentFingerprint = node.parentFingerprint ? node.parentFingerprint.toString('hex').padStart(8, '0') : '00000000';
    const chainCode = node.chainCode.toString('hex');
    const publicKey = node.publicKey.toString('hex');
    const version = isTestnet ? 
      (node.isNeutered() ? '043587cf' : '04358394') :
      (node.isNeutered() ? '0488b21e' : '0488ade4');

    // Prepare result
    const result = {
      version: `0x${version}`,
      network: isTestnet ? 'testnet' : 'mainnet',
      type: node.isNeutered() ? 'Public' : 'Private',
      depth: `0x${node.depth.toString(16).padStart(2, '0')}`,
      fingerprint: `0x${fingerprint}`,
      parentFingerprint: `0x${parentFingerprint}`,
      index: `0x${node.index.toString(16).padStart(8, '0')}`,
      chainCode: `0x${chainCode}`,
      publicKey: `0x${publicKey}`
    };

    if (options.verbose) {
      console.log(chalk.green('\nDecoded Extended Key:'));
      console.log(chalk.yellow('Version:          '), result.version);
      console.log(chalk.yellow('Network:          '), result.network);
      console.log(chalk.yellow('Type:             '), result.type);
      console.log(chalk.yellow('Depth:            '), result.depth);
      console.log(chalk.yellow('Parent FP:        '), result.parentFingerprint);
      console.log(chalk.yellow('Index:            '), result.index);
      console.log(chalk.yellow('Fingerprint:      '), result.fingerprint);
      console.log(chalk.yellow('Chain Code:       '), result.chainCode);
      console.log(chalk.yellow('Public Key:       '), result.publicKey);
    } else {
      console.log(JSON.stringify(result, null, 2));
    }

  } catch (error) {
    console.error(chalk.red('Error decoding key:'), error.message);
    process.exit(1);
  }
}

module.exports = decode;