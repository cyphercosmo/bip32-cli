const chalk = require('chalk');
const { BIP32Factory } = require('bip32');
const ecc = require('tiny-secp256k1');
const { isValidPath, isValidExtendedKey } = require('../utils/validation');
const { formatExtendedKey } = require('../utils/formatting');

// Initialize BIP32 factory with network support
const BIP32 = BIP32Factory(ecc);

// Hardened index offset (2^31)
const HARDENED_OFFSET = 0x80000000;

/**
 * Converts a path segment to its numeric index
 * @param {string} segment - Path segment (e.g., "0" or "0'" or "0h")
 * @returns {number} Numeric index
 */
function getPathIndex(segment) {
  // Remove the first character 'm' if present
  if (segment === 'm' || segment === 'M') return null;

  // Check if hardened
  const isHardened = segment.endsWith("'") || segment.endsWith("h");
  // Get the numeric value
  const index = parseInt(isHardened ? segment.slice(0, -1) : segment);

  // Add hardened offset if needed
  return isHardened ? index + HARDENED_OFFSET : index;
}

/**
 * Converts a BIP32 path to array of numeric indices
 * @param {string} path - BIP32 path (e.g., "m/0'/1/2h")
 * @returns {number[]} Array of numeric indices
 */
function pathToIndicies(path) {
  return path.split('/')
    .map(getPathIndex)
    .filter(index => index !== null);
}

function derive(options) {
  try {
    // Validate inputs
    if (!isValidExtendedKey(options.key)) {
      console.error(chalk.red('Error: Invalid extended key format'));
      process.exit(1);
    }

    // Convert path to standardized format (using apostrophe for hardened)
    const standardPath = options.path.replace(/h/g, "'");

    if (!isValidPath(standardPath)) {
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

    // Convert path to indices and derive
    const indices = pathToIndicies(standardPath);

    // Debug log for indices
    if (options.verbose) {
      console.log(chalk.blue('\nPath Indices:'));
      indices.forEach((index, i) => {
        const segment = standardPath.split('/')[i + 1];
        const isHardened = index >= HARDENED_OFFSET;
        console.log(chalk.blue(`${segment}: ${isHardened ? index - HARDENED_OFFSET : index}${isHardened ? "'" : ''} (raw: ${index})`));
      });
    }

    let node = parentNode;
    for (const index of indices) {
      node = node.derive(index);
    }

    // Prepare result
    const result = {
      path: standardPath,
      childPrivateKey: node.isNeutered() ? null : node.toBase58(),
      childPublicKey: node.neutered().toBase58(),
      fingerprint: node.fingerprint.toString('hex'),
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