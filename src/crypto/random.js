/**
 * Secure Random Number Generator
 * 
 * A minimal module for generating cryptographically secure random numbers
 * using the Web Crypto API.
 */

/**
 * Generate cryptographically secure random bytes
 * 
 * @param {number} length - Number of bytes to generate
 * @returns {Uint8Array} - Random bytes
 */
export function randomBytes(length) {
  // Use the Web Crypto API
  const array = new Uint8Array(length);
  
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(array);
  } else if (typeof window !== 'undefined' && window.crypto && window.crypto.getRandomValues) {
    window.crypto.getRandomValues(array);
  } else {
    throw new Error('Secure random number generation not supported by this environment');
  }
  
  return array;
}

/**
 * Generate a random integer within a range (inclusive)
 * 
 * @param {number} min - Minimum value (inclusive)
 * @param {number} max - Maximum value (inclusive)
 * @returns {number} - Random integer
 */
export function randomInt(min, max) {
  if (min > max) {
    throw new Error('Min value must be less than or equal to max value');
  }
  
  const range = max - min + 1;
  const bytesNeeded = Math.ceil(Math.log2(range) / 8);
  const mask = Math.pow(2, Math.ceil(Math.log2(range))) - 1;
  
  let value;
  do {
    const randomBytes = new Uint8Array(bytesNeeded);
    crypto.getRandomValues(randomBytes);
    
    value = 0;
    for (let i = 0; i < bytesNeeded; i++) {
      value = (value << 8) | randomBytes[i];
    }
    
    value = value & mask;
  } while (value >= range);
  
  return min + value;
}

/**
 * Generate a random string of specified length
 * 
 * @param {number} length - Length of the string
 * @param {string} charset - Character set to use (default: alphanumeric)
 * @returns {string} - Random string
 */
export function randomString(length, charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789') {
  const bytes = randomBytes(length);
  let result = '';
  
  for (let i = 0; i < length; i++) {
    result += charset.charAt(bytes[i] % charset.length);
  }
  
  return result;
} 