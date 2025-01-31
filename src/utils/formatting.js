const chalk = require('chalk');

/**
 * Formats extended key output with proper spacing and coloring
 * @param {string} label - The label for the key
 * @param {string} key - The extended key
 * @returns {string} Formatted string
 */
function formatExtendedKey(label, key) {
  return `${chalk.yellow(label + ':')} ${chalk.green(key)}`;
}

module.exports = {
  formatExtendedKey
};
