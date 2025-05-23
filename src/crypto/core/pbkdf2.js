/**
 * PBKDF2 Implementation
 * 
 * Provides PBKDF2 key derivation for the Essential level.
 */

/**
 * Class for PBKDF2 key derivation operations
 */
export class PBKDF2 {
  // Default parameters
  static DEFAULT_ITERATIONS = 100000;
  static DEFAULT_HASH = 'SHA-256';
  static DEFAULT_KEY_LENGTH = 256;
  
  /**
   * Derive a key using PBKDF2
   * 
   * @param {string} password - The password to derive from
   * @param {Uint8Array|string} salt - The salt to use
   * @param {number} [iterations=100000] - Number of iterations
   * @param {string} [hash='SHA-256'] - Hash algorithm to use
   * @param {number} [keyLength=256] - Length of the derived key in bits
   * @returns {Promise<ArrayBuffer>} - The derived key material
   */
  async deriveKey(password, salt, iterations = PBKDF2.DEFAULT_ITERATIONS, hash = PBKDF2.DEFAULT_HASH, keyLength = PBKDF2.DEFAULT_KEY_LENGTH) {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);
    
    // Normalize salt to Uint8Array
    let saltBuffer;
    if (typeof salt === 'string') {
      saltBuffer = encoder.encode(salt);
    } else {
      saltBuffer = salt;
    }
    
    // Import the password as a key
    const baseKey = await window.crypto.subtle.importKey(
      'raw',
      passwordBuffer,
      { name: 'PBKDF2' },
      false,
      ['deriveBits', 'deriveKey']
    );
    
    // Derive bits
    return window.crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: saltBuffer,
        iterations,
        hash
      },
      baseKey,
      keyLength
    );
  }
  
  /**
   * Derive an encryption key using PBKDF2
   * 
   * @param {string} password - The password to derive from
   * @param {Uint8Array|string} salt - The salt to use
   * @param {string} [algorithm='AES-GCM'] - The algorithm to use for the key
   * @param {number} [keyLength=256] - Length of the key in bits
   * @param {number} [iterations=100000] - Number of iterations
   * @param {string} [hash='SHA-256'] - Hash algorithm to use
   * @returns {Promise<CryptoKey>} - The derived key
   */
  async deriveEncryptionKey(password, salt, algorithm = 'AES-GCM', keyLength = 256, iterations = PBKDF2.DEFAULT_ITERATIONS, hash = PBKDF2.DEFAULT_HASH) {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);
    
    // Normalize salt to Uint8Array
    let saltBuffer;
    if (typeof salt === 'string') {
      saltBuffer = encoder.encode(salt);
    } else {
      saltBuffer = salt;
    }
    
    // Import the password as a key
    const baseKey = await window.crypto.subtle.importKey(
      'raw',
      passwordBuffer,
      { name: 'PBKDF2' },
      false,
      ['deriveBits', 'deriveKey']
    );
    
    // Derive a key for the specified algorithm
    return window.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: saltBuffer,
        iterations,
        hash
      },
      baseKey,
      {
        name: algorithm,
        length: keyLength
      },
      true,
      ['encrypt', 'decrypt']
    );
  }
  
  /**
   * Generate a random salt
   * 
   * @param {number} [length=16] - Length of the salt in bytes
   * @returns {Uint8Array} - The generated salt
   */
  generateSalt(length = 16) {
    return window.crypto.getRandomValues(new Uint8Array(length));
  }
  
  /**
   * Convert a derived key to hex string
   * 
   * @param {ArrayBuffer} keyMaterial - The derived key material
   * @returns {string} - The hex string
   */
  keyToHex(keyMaterial) {
    const keyArray = Array.from(new Uint8Array(keyMaterial));
    return keyArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }
  
  /**
   * Convert a derived key to Base64 string
   * 
   * @param {ArrayBuffer} keyMaterial - The derived key material
   * @returns {string} - The base64 string
   */
  keyToBase64(keyMaterial) {
    const bytes = new Uint8Array(keyMaterial);
    let binary = '';
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }
} 