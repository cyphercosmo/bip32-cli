/**
 * Validates a hexadecimal string
 * @param {string} hex - The hex string to validate
 * @returns {boolean} True if valid hex string
 */
function isValidHexString(hex) {
  if (!hex || typeof hex !== 'string') return false;
  return /^[0-9a-fA-F]+$/.test(hex) && hex.length % 2 === 0;
}

/**
 * Validates BIP32 derivation path
 * @param {string} path - The derivation path to validate
 * @returns {boolean} True if valid path
 */
function isValidPath(path) {
  if (!path || typeof path !== 'string') return false;
  
  // Check if path starts with 'm' or 'M' and follows valid format
  const regex = /^[mM](?:\/\d+'?)*$/;
  return regex.test(path);
}

/**
 * Validates extended key format
 * @param {string} key - The extended key to validate
 * @returns {boolean} True if valid extended key
 */
function isValidExtendedKey(key) {
  if (!key || typeof key !== 'string') return false;
  
  // Check if key starts with xprv or xpub and is base58 encoded
  return /^(xprv|xpub)/.test(key) && /^[1-9A-HJ-NP-Za-km-z]+$/.test(key);
}

module.exports = {
  isValidHexString,
  isValidPath,
  isValidExtendedKey
};
