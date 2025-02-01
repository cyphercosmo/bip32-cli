#!/usr/bin/env node

const { program } = require('commander');
const chalk = require('chalk');
const generate = require('./commands/generate');
const derive = require('./commands/derive');
const decode = require('./commands/decode');

// Set up CLI program
program
  .name('bip32-cli')
  .description('CLI tool for BIP32 key operations')
  .version('1.0.0');

// Generate command
program
  .command('generate')
  .description('Generate a new BIP32 master key')
  .option('-s, --seed <hex>', 'Specify seed in hexadecimal format')
  .option('-t, --testnet', 'Generate testnet keys')
  .option('-v, --verbose', 'Show detailed output')
  .action(generate);

// Derive command
program
  .command('derive')
  .description('Derive child keys from a parent key')
  .requiredOption('-k, --key <string>', 'Parent extended key (xprv/xpub/tprv/tpub)')
  .requiredOption('-p, --path <string>', 'Derivation path (e.g., m/0/0)')
  .option('-v, --verbose', 'Show detailed output')
  .action(derive);

// Decode command
program
  .command('decode')
  .description('Decode and display information about an extended key')
  .requiredOption('-k, --key <string>', 'Extended key to decode (xprv/xpub/tprv/tpub)')
  .option('-v, --verbose', 'Show detailed output')
  .action(decode);

// Error handling for unknown commands
program.on('command:*', function () {
  console.error(chalk.red('Invalid command: %s\nSee --help for a list of available commands.'),
    program.args.join(' '));
  process.exit(1);
});

// Parse command line arguments
program.parse(process.argv);

// Show help if no arguments provided
if (!process.argv.slice(2).length) {
  program.outputHelp();
}