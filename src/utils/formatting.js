const chalk = require('chalk');

/**
 * Formats a number or buffer as hex string with optional padding
 * @param {Buffer|Uint8Array|number} value - Value to convert to hex
 * @param {number} padLength - Optional padding length
 * @returns {string} Formatted hex string
 */
function formatHex(value, padLength = 0) {
  if (value instanceof Uint8Array || Buffer.isBuffer(value)) {
    return Buffer.from(value).toString('hex').padStart(padLength || 0, '0');
  }
  return (typeof value === 'number' ? value.toString(16) : '').padStart(padLength, '0');
}

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
  formatHex,
  formatExtendedKey
};