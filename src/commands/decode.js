const chalk = require('chalk');
const { BIP32Factory } = require('bip32');
const ecc = require('tiny-secp256k1');
const crypto = require('crypto');
const base58check = require('bs58check');
const { isValidExtendedKey } = require('../utils/validation');

// Initialize BIP32 factory
const BIP32 = BIP32Factory(ecc);

/**
 * Calculate hash160 (RIPEMD160(SHA256(data)))
 * @param {Buffer} data - Data to hash
 * @returns {Buffer} hash160 value as Buffer
 */
function calculateHash160(data) {
  return crypto
    .createHash('ripemd160')
    .update(
      crypto.createHash('sha256').update(data).digest()
    )
    .digest();
}

/**
 * Calculate fingerprint from public key
 * @param {Buffer} publicKey - Public key buffer
 * @returns {string} Fingerprint as hex string
 */
function calculateFingerprint(publicKey) {
  // If public key is not compressed, compress it
  const compressedPubKey = publicKey.length === 33 ? publicKey : ecc.pointCompress(publicKey, true);
  return calculateHash160(compressedPubKey).slice(0, 4).toString('hex');
}

/**
 * Formats a Buffer or Uint8Array as a continuous hex string
 * @param {Buffer|Uint8Array|number} value - Value to convert
 * @param {number} padLength - Optional padding length
 * @returns {string} Formatted hex string
 */
function formatHex(value, padLength = 0) {
  try {
    if (value instanceof Uint8Array || Buffer.isBuffer(value)) {
      const buffer = Buffer.from(value);
      const hexString = buffer.toString('hex');
      return hexString.padStart(padLength || hexString.length, '0');
    } else if (typeof value === 'number') {
      return value.toString(16).padStart(padLength, '0');
    }
    return ''.padStart(padLength || 2, '0');
  } catch (error) {
    console.error('Error in formatHex:', error);
    return ''.padStart(padLength || 2, '0');
  }
}

function decode(options) {
  try {
    const { key } = options;

    // Validate input
    if (!isValidExtendedKey(key)) {
      console.error(chalk.red('Error: Invalid extended key format'));
      process.exit(1);
    }

    // Decode base58check string to get raw bytes
    const rawBytes = base58check.decode(key);

    // Extract the version and parent fingerprint from raw bytes
    const version = rawBytes.slice(0, 4).toString('hex');
    const parentFingerprint = rawBytes.slice(4, 8).toString('hex');

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

    // Parse the key using bip32
    const node = BIP32.fromBase58(key, network);

    // Get version based on network and key type
    const versionHex = isTestnet ? 
      (node.isNeutered() ? '043587cf' : '04358394') :
      (node.isNeutered() ? '0488b21e' : '0488ade4');

    // Calculate hash160 from the public key
    const hash160 = calculateHash160(node.publicKey);
    const fingerprint = calculateFingerprint(node.publicKey);

    // Format all values as continuous hex strings
    const result = {
      version: versionHex,
      network: isTestnet ? 'testnet' : 'mainnet',
      type: node.isNeutered() ? 'Public' : 'Private',
      depth: formatHex(node.depth, 2),
      parentFingerprint,
      index: formatHex(node.index, 8),
      fingerprint,
      chainCode: formatHex(node.chainCode),
      publicKey: formatHex(node.publicKey),
      hash160: hash160.toString('hex')
    };

    // Add privateKey if available
    if (!node.isNeutered()) {
      result.privateKey = formatHex(node.privateKey);
    }

    if (options.verbose) {
      console.log(chalk.green('\nDecoded Extended Key:'));
      console.log(chalk.yellow('Version:          '), `0x${result.version}`);
      console.log(chalk.yellow('Network:          '), result.network);
      console.log(chalk.yellow('Type:             '), result.type);
      console.log(chalk.yellow('Depth:            '), `0x${result.depth}`);
      console.log(chalk.yellow('Parent FP:        '), `0x${result.parentFingerprint}`);
      console.log(chalk.yellow('Index:            '), `0x${result.index}`);
      console.log(chalk.yellow('Fingerprint:      '), `0x${result.fingerprint}`);
      console.log(chalk.yellow('Chain Code:       '), `0x${result.chainCode}`);
      if (result.privateKey) {
        console.log(chalk.yellow('Private Key:      '), `0x${result.privateKey}`);
      }
      console.log(chalk.yellow('Public Key:       '), `0x${result.publicKey}`);
      console.log(chalk.yellow('Hash160:          '), `0x${result.hash160}`);
    } else {
      console.log(JSON.stringify(result, null, 2));
    }

  } catch (error) {
    console.error(chalk.red('Error decoding key:'), error.message);
    process.exit(1);
  }
}

module.exports = decode;