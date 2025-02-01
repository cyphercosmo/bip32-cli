const chalk = require('chalk');
const { BIP32Factory } = require('bip32');
const ecc = require('tiny-secp256k1');
const { isValidExtendedKey } = require('../utils/validation');
const { getNetwork } = require('../utils/networks');

// Initialize BIP32 factory
const BIP32 = BIP32Factory(ecc);

/**
 * Formats a number or buffer as hex string with optional padding
 */
function formatHex(value, padLength = 0) {
  if (value instanceof Uint8Array || Buffer.isBuffer(value)) {
    return Buffer.from(value).toString('hex').padStart(padLength || 0, '0');
  }
  return (typeof value === 'number' ? value.toString(16) : '').padStart(padLength, '0');
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
    const network = getNetwork(isTestnet);

    // Parse the key using bip32
    const node = BIP32.fromBase58(key, network);

    // Get version based on key type
    const version = isTestnet ? 
      (node.isNeutered() ? '043587cf' : '04358394') :
      (node.isNeutered() ? '0488b21e' : '0488ade4');

    // Format the result using bip32's built-in properties
    const result = {
      version,
      network: isTestnet ? 'testnet' : 'mainnet',
      type: node.isNeutered() ? 'Public' : 'Private',
      depth: formatHex(node.depth, 2),
      parentFingerprint: node.depth === 0 ? '00000000' : formatHex(node.parentFingerprint, 8),
      index: formatHex(node.index, 8),
      fingerprint: formatHex(node.fingerprint, 8),
      chainCode: formatHex(node.chainCode),
      publicKey: formatHex(node.publicKey),
      hash160: formatHex(node.identifier)
    };

    // Add privateKey if available
    if (!node.isNeutered() && node.privateKey) {
      result.privateKey = formatHex(node.privateKey);
    }

    if (options.verbose) {
      console.log(chalk.blue('\nDebug Info:'));
      console.log('Raw Extended Key:', key);

      console.log('\nPublic Key Analysis:');
      console.log('Raw Public Key:', formatHex(node.publicKey));
      console.log('Is Compressed:', node.publicKey[0] === 0x02 || node.publicKey[0] === 0x03);
      console.log('Length:', node.publicKey.length);
      console.log('First byte:', `0x${node.publicKey[0].toString(16)}`);
      console.log('Public Key Buffer:', formatHex(node.publicKey));
      console.log('HASH160:', formatHex(node.identifier));

      console.log('\nBIP32 Node Details:');
      if (node.privateKey) {
        console.log('Private Key:', formatHex(node.privateKey));
      } else {
        console.log('Private Key: N/A');
      }
      console.log('Chain Code:', formatHex(node.chainCode));
      console.log('Network:', result.network);
      console.log('Depth:', node.depth);
      console.log('Index:', node.index);
      console.log('Parent Fingerprint:', result.parentFingerprint);

      console.log(chalk.green('\nDecoded Extended Key:'));
      Object.entries(result).forEach(([key, value]) => {
        const shouldHaveHexPrefix = ['version', 'depth', 'parentFingerprint', 'index', 'fingerprint', 'chainCode', 'publicKey', 'privateKey', 'hash160'].includes(key);
        const displayValue = shouldHaveHexPrefix ? `0x${value}` : value;
        console.log(chalk.yellow(`${key.padEnd(16)}`), displayValue);
      });
    } else {
      console.log(JSON.stringify(result, null, 2));
    }

  } catch (error) {
    console.error(chalk.red('Error decoding key:'), error.message);
    process.exit(1);
  }
}

module.exports = decode;