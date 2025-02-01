const chalk = require('chalk');
const { BIP32Factory } = require('bip32');
const ecc = require('tiny-secp256k1');
const crypto = require('crypto');
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
  // Check if public key starts with 0x02 or 0x03 (compressed format)
  // If not, the library might be giving us uncompressed format
  const compressedPubKey = publicKey[0] === 0x02 || publicKey[0] === 0x03 
    ? publicKey 
    : ecc.pointCompress(publicKey, true);

  const hash160 = calculateHash160(compressedPubKey);
  return hash160.slice(0, 4).toString('hex');
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

    // For debugging, let's log the raw key data
    if (options.verbose) {
      console.log(chalk.blue('\nDebug Info:'));
      console.log('Raw Extended Key:', key);
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

    // Calculate hash160 from the public key
    const hash160 = calculateHash160(node.publicKey).toString('hex');

    // For master keys (depth 0), fingerprint should be 0x00000000
    // For derived keys, use the parent fingerprint from the key itself
    const parentFingerprint = node.depth === 0 ? '00000000' : formatHex(node.parentFingerprint, 8);

    // Calculate current node's fingerprint from its public key
    const nodeFingerprint = calculateFingerprint(node.publicKey);

    // Add debug info for public key formats
    if (options.verbose) {
      console.log('\nPublic Key Analysis:');
      console.log('Raw Public Key:', node.publicKey.toString('hex'));
      console.log('Is Compressed:', node.publicKey[0] === 0x02 || node.publicKey[0] === 0x03);
      console.log('Length:', node.publicKey.length);
      console.log('First byte:', `0x${node.publicKey[0].toString(16)}`);
      console.log('Public Key Buffer:', Buffer.from(node.publicKey).toString('hex'));
      console.log('HASH160 of Public Key:', hash160);
      console.log('First 4 bytes of HASH160:', hash160.slice(0, 8));

      // Additional BIP32 node details
      console.log('\nBIP32 Node Details:');
      console.log('Private Key:', node.privateKey ? node.privateKey.toString('hex') : 'N/A');
      console.log('Chain Code:', node.chainCode.toString('hex'));
      console.log('Network:', isTestnet ? 'testnet' : 'mainnet');
      console.log('Depth:', node.depth);
      console.log('Index:', node.index);
      console.log('Parent Fingerprint:', parentFingerprint);
    }

    // Format all values as continuous hex strings
    const result = {
      version,
      network: isTestnet ? 'testnet' : 'mainnet',
      type: node.isNeutered() ? 'Public' : 'Private',
      depth: formatHex(node.depth, 2),
      parentFingerprint,
      index: formatHex(node.index, 8),
      fingerprint: nodeFingerprint,
      chainCode: formatHex(node.chainCode),
      publicKey: formatHex(node.publicKey),
      hash160
    };

    // Add privateKey if available
    if (!node.isNeutered() && node.privateKey) {
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