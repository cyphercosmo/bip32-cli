const chalk = require('chalk');
const crypto = require('crypto');
const { BIP32Factory } = require('bip32');
const ecc = require('tiny-secp256k1');
const { isValidHexString } = require('../utils/validation');
const { formatExtendedKey } = require('../utils/formatting');

// Initialize BIP32 factory
const BIP32 = BIP32Factory(ecc);

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

    // Determine network (default to mainnet)
    const network = options.testnet ? {
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

    // Generate master node with network parameters
    const node = BIP32.fromSeed(seed, network);

    // Format output
    const result = {
      masterPrivateKey: node.toBase58(),
      masterPublicKey: node.neutered().toBase58(),
      fingerprint: node.fingerprint.toString('hex'),
      seed: seed.toString('hex'),
      network: options.testnet ? 'testnet' : 'mainnet'
    };

    if (options.verbose) {
      console.log(chalk.green('\nGenerated BIP32 Master Keys:'));
      console.log(chalk.yellow('Network:'), result.network);
      console.log(formatExtendedKey('Master Private Key', result.masterPrivateKey));
      console.log(formatExtendedKey('Master Public Key', result.masterPublicKey));
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