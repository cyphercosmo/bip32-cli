const chalk = require('chalk');
const BIP32 = require('bip32');
const { isValidPath, isValidExtendedKey } = require('../utils/validation');
const { formatExtendedKey } = require('../utils/formatting');

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

    // Parse the parent key
    const parentNode = BIP32.fromBase58(options.key);
    
    // Derive child key
    const childNode = parentNode.derivePath(options.path);

    // Prepare result
    const result = {
      path: options.path,
      childPrivateKey: childNode.isNeutered() ? null : childNode.toBase58(),
      childPublicKey: childNode.neutered().toBase58(),
      fingerprint: childNode.fingerprint.toString('hex')
    };

    if (options.verbose) {
      console.log(chalk.green('\nDerived Keys:'));
      console.log(chalk.yellow('Path:'), result.path);
      if (result.childPrivateKey) {
        console.log(formatExtendedKey('Child Private Key (xprv)', result.childPrivateKey));
      }
      console.log(formatExtendedKey('Child Public Key (xpub)', result.childPublicKey));
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
