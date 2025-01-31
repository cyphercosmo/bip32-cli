const chalk = require('chalk');
const crypto = require('crypto');
const BIP32 = require('bip32');
const { isValidHexString } = require('../utils/validation');
const { formatExtendedKey } = require('../utils/formatting');

function generate(options) {
  try {
    let seed;
    
    if (options.seed) {
      if (!isValidHexString(options.seed)) {
        console.error(chalk.red('Error: Invalid seed format. Must be a valid hexadecimal string.'));
        process.exit(1);
      }
      seed = Buffer.from(options.seed, 'hex');
    } else {
      // Generate random seed (256 bits)
      seed = crypto.randomBytes(32);
    }

    // Generate master node
    const node = BIP32.fromSeed(seed);

    // Format output
    const result = {
      masterPrivateKey: node.toBase58(),
      masterPublicKey: node.neutered().toBase58(),
      fingerprint: node.fingerprint.toString('hex'),
      seed: seed.toString('hex')
    };

    if (options.verbose) {
      console.log(chalk.green('\nGenerated BIP32 Master Keys:'));
      console.log(formatExtendedKey('Master Private Key (xprv)', result.masterPrivateKey));
      console.log(formatExtendedKey('Master Public Key (xpub)', result.masterPublicKey));
      console.log(chalk.yellow('Fingerprint:'), result.fingerprint);
      console.log(chalk.yellow('Seed (hex):'), result.seed);
    } else {
      console.log(result.masterPrivateKey);
    }

  } catch (error) {
    console.error(chalk.red('Error generating keys:'), error.message);
    process.exit(1);
  }
}

module.exports = generate;
