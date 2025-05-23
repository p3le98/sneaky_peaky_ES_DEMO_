/**
 * SHA-256 Implementation
 * 
 * Provides SHA-256 hashing for the Essential level.
 */

/**
 * Class for SHA-256 hashing operations
 */
export class SHA256 {
  /**
   * Hash a message using SHA-256
   * 
   * @param {string|ArrayBuffer} message - The message to hash
   * @returns {Promise<ArrayBuffer>} - The hash result
   */
  async hash(message) {
    let data;
    
    if (typeof message === 'string') {
      // Convert string to ArrayBuffer
      const encoder = new TextEncoder();
      data = encoder.encode(message);
    } else {
      data = message;
    }
    
    // Perform the hash
    return window.crypto.subtle.digest('SHA-256', data);
  }
  
  /**
   * Hash a message using SHA-256 and return the result as a hex string
   * 
   * @param {string|ArrayBuffer} message - The message to hash
   * @returns {Promise<string>} - The hash result as a hex string
   */
  async hashToHex(message) {
    const hashBuffer = await this.hash(message);
    return this.arrayBufferToHex(hashBuffer);
  }
  
  /**
   * Hash a message using SHA-256 and return the result as a base64 string
   * 
   * @param {string|ArrayBuffer} message - The message to hash
   * @returns {Promise<string>} - The hash result as a base64 string
   */
  async hashToBase64(message) {
    const hashBuffer = await this.hash(message);
    return this.arrayBufferToBase64(hashBuffer);
  }
  
  /**
   * Convert ArrayBuffer to hex string
   * 
   * @private
   * @param {ArrayBuffer} buffer - The buffer to convert
   * @returns {string} - The hex string
   */
  arrayBufferToHex(buffer) {
    const hashArray = Array.from(new Uint8Array(buffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }
  
  /**
   * Convert ArrayBuffer to Base64 string
   * 
   * @private
   * @param {ArrayBuffer} buffer - The buffer to convert
   * @returns {string} - The base64 string
   */
  arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }
} 