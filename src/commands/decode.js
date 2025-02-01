const chalk = require('chalk');
const { BIP32Factory } = require('bip32');
const ecc = require('tiny-secp256k1');
const { isValidExtendedKey } = require('../utils/validation');

// Initialize BIP32 factory
const BIP32 = BIP32Factory(ecc);

/**
 * Safely converts a value to a hex string with padding
 * @param {Buffer|number} value - The value to convert
 * @param {number} padLength - Length to pad the hex string to
 * @returns {string} Padded hex string
 */
function toSafeHex(value, padLength = 0) {
  if (Buffer.isBuffer(value)) {
    return value.toString('hex').padStart(padLength || value.length * 2, '0');
  }
  if (typeof value === 'number') {
    return value.toString(16).padStart(padLength, '0');
  }
  return '00'.repeat(padLength / 2);
}

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

    // Get version based on network and key type
    const version = isTestnet ? 
      (node.isNeutered() ? '043587cf' : '04358394') :
      (node.isNeutered() ? '0488b21e' : '0488ade4');

    // Format all hex values consistently
    const result = {
      version: `0x${version}`,
      network: isTestnet ? 'testnet' : 'mainnet',
      type: node.isNeutered() ? 'Public' : 'Private',
      depth: `0x${toSafeHex(node.depth, 2)}`,
      parentFingerprint: `0x${toSafeHex(node.parentFingerprint, 8)}`,
      index: `0x${toSafeHex(node.index, 8)}`,
      fingerprint: `0x${toSafeHex(node.fingerprint, 8)}`,
      chainCode: `0x${Buffer.isBuffer(node.chainCode) ? node.chainCode.toString('hex') : ''}`,
      publicKey: `0x${Buffer.isBuffer(node.publicKey) ? node.publicKey.toString('hex') : ''}`
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