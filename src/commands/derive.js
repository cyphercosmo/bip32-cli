const chalk = require('chalk');
const { BIP32Factory } = require('bip32');
const ecc = require('tiny-secp256k1');
const { isValidPath, isValidExtendedKey } = require('../utils/validation');
const { formatExtendedKey, formatHex } = require('../utils/formatting');
const { getNetwork } = require('../utils/networks');

// Initialize BIP32 factory
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

  // Check if hardened (supports both ' and h notation)
  const isHardened = segment.endsWith("'") || segment.endsWith("h");

  // Get the numeric value, removing the hardened indicator
  const index = parseInt(isHardened ? segment.slice(0, -1) : segment);

  if (isNaN(index) || index < 0) {
    throw new Error(`Invalid path segment: ${segment}`);
  }

  // Add hardened offset if needed
  return isHardened ? index + HARDENED_OFFSET : index;
}

/**
 * Converts a BIP32 path to array of numeric indices
 * @param {string} path - BIP32 path (e.g., "m/0'/1/2h")
 * @returns {number[]} Array of numeric indices
 */
function pathToIndicies(path) {
  return path
    .split('/')
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

    if (!isValidPath(options.path)) {
      console.error(chalk.red('Error: Invalid derivation path format'));
      process.exit(1);
    }

    // Determine network from key prefix and get network config
    const isTestnet = options.key.startsWith('t');
    const network = getNetwork(isTestnet);

    // Parse the parent key with appropriate network
    const parentNode = BIP32.fromBase58(options.key, network);

    // Convert path to indices and derive
    const indices = pathToIndicies(options.path);

    // Debug log for indices
    if (options.verbose) {
      console.log(chalk.blue('\nPath Analysis:'));
      indices.forEach((index, i) => {
        const segment = options.path.split('/')[i + 1];
        const isHardened = index >= HARDENED_OFFSET;
        const displayIndex = isHardened ? index - HARDENED_OFFSET : index;
        console.log(chalk.blue(
          `${segment.padEnd(4)}: ` +
          `index=0x${formatHex(displayIndex, 8)} ` +
          `(raw=0x${formatHex(index, 8)})`
        ));
      });
    }

    // Derive child node
    let node = parentNode;
    for (const index of indices) {
      node = node.derive(index);
    }

    // Prepare result
    const result = {
      network: isTestnet ? 'testnet' : 'mainnet',
      path: options.path,
      parentFingerprint: formatHex(node.parentFingerprint, 8),
      fingerprint: formatHex(node.fingerprint, 8),
      childPrivateKey: node.isNeutered() ? null : node.toBase58(),
      childPublicKey: node.neutered().toBase58()
    };

    if (options.verbose) {
      console.log(chalk.green('\nDerived Keys:'));
      console.log(chalk.yellow('Network:          '), result.network);
      console.log(chalk.yellow('Path:             '), result.path);
      console.log(chalk.yellow('Parent Fingerprint:'), `0x${result.parentFingerprint}`);
      console.log(chalk.yellow('Child Fingerprint: '), `0x${result.fingerprint}`);
      if (result.childPrivateKey) {
        console.log(formatExtendedKey('Child Private Key', result.childPrivateKey));
      }
      console.log(formatExtendedKey('Child Public Key ', result.childPublicKey));
    } else {
      console.log(result.childPrivateKey || result.childPublicKey);
    }

  } catch (error) {
    console.error(chalk.red('Error deriving keys:'), error.message);
    process.exit(1);
  }
}

module.exports = derive;