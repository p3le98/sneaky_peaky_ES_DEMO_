"use strict";
// import { randomBytes, subtle } from 'crypto';
// import { v4 as uuidv4 } from 'uuid';
Object.defineProperty(exports, "__esModule", { value: true });
exports.MetadataProtection = void 0;
/**
 * Metadata Protection for Essential Level
 *
 * Provides traffic analysis prevention through:
 * - Message padding
 * - Timing obfuscation
 * - Metadata encryption
 */
class MetadataProtection {
    constructor() {
        // Padding size increments
        this.PADDING_BLOCK_SIZE = 256;
        // Maximum padding size (to avoid excessive resource use)
        this.MAX_PADDING_SIZE = 1024 * 10; // 10 KB
        // Timing obfuscation parameters
        this.MIN_DELAY_MS = 10;
        this.MAX_DELAY_MS = 500;
        this.TIMING_WINDOW_MS = 100;
    }
    /**
     * Initialize the metadata protection module
     */
    async initialize() {
        // No initialization needed for now
    }
    /**
     * Protect a message by padding and adding metadata protection
     */
    async protectMessage(options) {
        // Generate a unique message ID
        const messageId = this.generateUUID();
        // Encrypt and embed metadata
        const embeddedContent = await this.embedMetadata(options.content, options.metadata || {}, messageId);
        // Apply padding to prevent traffic analysis
        const { paddedContent, paddedLength } = this.applyPadding(embeddedContent);
        // Determine message delivery timing
        const delay = this.calculateMessageDelay();
        // Apply timing delay if necessary
        if (delay > 0) {
            await this.applyTimingDelay(delay);
        }
        return {
            content: paddedContent,
            paddedLength,
            messageId
        };
    }
    /**
     * Unprotect a message by removing padding and extracting metadata
     */
    async unprotectMessage(options) {
        // Remove padding
        const unpaddedContent = this.removePadding(options.content);
        // Extract metadata
        const { originalContent, metadata } = await this.extractMetadata(unpaddedContent, options.messageId);
        return {
            content: originalContent,
            metadata
        };
    }
    /**
     * Embed encrypted metadata into the message
     */
    async embedMetadata(content, metadata, messageId) {
        // Serialize metadata
        const metadataStr = JSON.stringify({
            ...metadata,
            _mid: messageId,
            _ts: Date.now()
        });
        // Encrypt metadata
        const metadataKey = await this.deriveMetadataKey(messageId);
        const iv = this.getRandomBytes(12);
        const encryptedMetadata = await this.encryptMetadata(metadataStr, metadataKey, iv);
        // Encode IV and encrypted metadata in base64
        const encodedIV = this.arrayBufferToBase64(iv);
        const encodedMetadata = this.arrayBufferToBase64(encryptedMetadata);
        // Format: content + separator + IV + separator + encrypted metadata
        return `${content}|METADATA|${encodedIV}|${encodedMetadata}`;
    }
    /**
     * Extract and decrypt metadata from the message
     */
    async extractMetadata(content, messageId) {
        // Split content and metadata
        const parts = content.split('|METADATA|');
        if (parts.length < 3) {
            // No metadata found, return original content
            return {
                originalContent: content,
                metadata: {}
            };
        }
        const originalContent = parts[0];
        const encodedIV = parts[1];
        const encodedMetadata = parts[2];
        // Decode IV and encrypted metadata
        const iv = this.base64ToArrayBuffer(encodedIV);
        const encryptedMetadata = this.base64ToArrayBuffer(encodedMetadata);
        // Derive metadata key
        const metadataKey = await this.deriveMetadataKey(messageId);
        // Decrypt metadata
        const metadataStr = await this.decryptMetadata(encryptedMetadata, metadataKey, iv);
        // Parse metadata
        const metadata = JSON.parse(metadataStr);
        // Remove internal properties
        delete metadata._mid;
        delete metadata._ts;
        return {
            originalContent,
            metadata
        };
    }
    /**
     * Apply padding to prevent traffic analysis
     */
    applyPadding(content) {
        // Calculate current length
        const contentLength = content.length;
        // Calculate target length (next multiple of PADDING_BLOCK_SIZE)
        const targetLength = Math.min(Math.ceil(contentLength / this.PADDING_BLOCK_SIZE) * this.PADDING_BLOCK_SIZE, contentLength + this.MAX_PADDING_SIZE);
        // Calculate how much padding we need
        const paddingLength = targetLength - contentLength;
        // Generate random padding
        const padding = Array(paddingLength)
            .fill(0)
            .map(() => String.fromCharCode(Math.floor(Math.random() * 26) + 97))
            .join('');
        // Format: content + separator + padding length + separator + padding
        return {
            paddedContent: `${content}|PAD|${paddingLength}|${padding}`,
            paddedLength: targetLength
        };
    }
    /**
     * Remove padding from padded content
     */
    removePadding(paddedContent) {
        // Split by padding separator
        const parts = paddedContent.split('|PAD|');
        if (parts.length < 2) {
            // No padding found, return original content
            return paddedContent;
        }
        // Extract original content
        return parts[0];
    }
    /**
     * Calculate message delivery delay for timing obfuscation
     */
    calculateMessageDelay() {
        // Use a random delay within the timing window
        return Math.floor(Math.random() * (this.MAX_DELAY_MS - this.MIN_DELAY_MS) + this.MIN_DELAY_MS);
    }
    /**
     * Apply timing delay for message delivery
     */
    async applyTimingDelay(delayMs) {
        return new Promise(resolve => setTimeout(resolve, delayMs));
    }
    /**
     * Derive a key for metadata encryption
     */
    async deriveMetadataKey(messageId) {
        // Use message ID as the base for the key
        const encoder = new TextEncoder();
        const keyMaterial = encoder.encode(messageId);
        // Import as raw key material
        const baseKey = await window.crypto.subtle.importKey('raw', keyMaterial, { name: 'PBKDF2' }, false, ['deriveBits', 'deriveKey']);
        // Derive the actual encryption key
        return window.crypto.subtle.deriveKey({
            name: 'PBKDF2',
            salt: encoder.encode('metadata-protection-salt'),
            iterations: 1000,
            hash: 'SHA-256'
        }, baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    }
    /**
     * Encrypt metadata with AES-GCM
     */
    async encryptMetadata(metadataStr, key, iv) {
        const encoder = new TextEncoder();
        const data = encoder.encode(metadataStr);
        return window.crypto.subtle.encrypt({
            name: 'AES-GCM',
            iv
        }, key, data);
    }
    /**
     * Decrypt metadata with AES-GCM
     */
    async decryptMetadata(encryptedMetadata, key, iv) {
        const decrypted = await window.crypto.subtle.decrypt({
            name: 'AES-GCM',
            iv
        }, key, encryptedMetadata);
        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    }
    /**
     * Generate a random UUID
     */
    generateUUID() {
        // Simple UUID v4 implementation
        const bytes = this.getRandomBytes(16);
        bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
        bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant
        return [
            this.byteToHex(bytes, 0, 4),
            this.byteToHex(bytes, 4, 6),
            this.byteToHex(bytes, 6, 8),
            this.byteToHex(bytes, 8, 10),
            this.byteToHex(bytes, 10, 16)
        ].join('-');
    }
    /**
     * Convert bytes to hex string
     */
    byteToHex(bytes, start, end) {
        const hexChars = [];
        for (let i = start; i < end; i++) {
            const byte = bytes[i];
            hexChars.push((byte >>> 4).toString(16));
            hexChars.push((byte & 0xF).toString(16));
        }
        return hexChars.join('');
    }
    /**
     * Get random bytes using the Web Crypto API
     */
    getRandomBytes(length) {
        return window.crypto.getRandomValues(new Uint8Array(length));
    }
    /**
     * Convert ArrayBuffer to Base64 string
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
    /**
     * Convert Base64 string to ArrayBuffer
     */
    base64ToArrayBuffer(base64) {
        const binary_string = window.atob(base64);
        const len = binary_string.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binary_string.charCodeAt(i);
        }
        return bytes.buffer;
    }
    /**
     * Clean up resources
     */
    async destroy() {
        // No resources to clean up
    }
}
exports.MetadataProtection = MetadataProtection;
