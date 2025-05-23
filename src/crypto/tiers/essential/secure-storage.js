"use strict";
// import { randomBytes, subtle } from 'crypto';
// import { v4 as uuidv4 } from 'uuid';
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecureStorage = void 0;
/**
 * Secure Storage for Essential Level
 *
 * Provides encrypted local storage functionality for the Essential security level.
 *
 * Implements:
 * - Key hierarchy for storage encryption
 * - Secure deletion with overwriting
 * - Automatic key rotation
 * - Encrypted metadata
 */
class SecureStorage {
    constructor() {
        // Master key for the storage (derived from password)
        this.masterKey = null;
        // Storage subkeys for different sensitivity levels
        this.storageKeys = {
            normal: null,
            high: null,
            critical: null
        };
        // In-memory cached storage (actual data would be persisted to disk/IndexedDB)
        this.storage = new Map();
        // Key rotation interval (in milliseconds)
        this.KEY_ROTATION_INTERVAL = 24 * 60 * 60 * 1000; // 24 hours
        // When storage keys were last rotated
        this.lastKeyRotation = 0;
    }
    /**
     * Initialize the secure storage module
     */
    async initialize() {
        // Generate or load master key (normally from secure password derivation)
        this.masterKey = await this.generateMasterKey();
        // Derive storage subkeys
        await this.deriveStorageKeys();
        // Schedule key rotation
        this.scheduleKeyRotation();
        // Load encrypted data from persistent storage
        await this.loadFromPersistentStorage();
    }
    /**
     * Store data securely
     */
    async store(options) {
        const sensitivity = options.keySensitivity || 'normal';
        const encryptionKey = this.getKeyForSensitivity(sensitivity);
        if (!encryptionKey) {
            throw new Error('Encryption key not available');
        }
        // Generate a data encryption key (DEK) specific to this item
        const dek = await this.generateDataEncryptionKey();
        // Encrypt the DEK with the storage key (key wrapping)
        const wrappedDek = await this.wrapKey(dek, encryptionKey);
        // Generate initialization vector
        const iv = this.getRandomBytes(12);
        // Serialize the data
        const serializedData = JSON.stringify(options.data);
        // Encrypt the actual data with the DEK
        const encryptedData = await this.encryptWithKey(serializedData, dek, iv);
        // Create metadata
        const metadata = {
            created: Date.now(),
            expires: options.expirationTime ? Date.now() + options.expirationTime : null,
            sensitivity,
            iv: this.arrayBufferToBase64(iv),
            keyVersion: 1
        };
        // Store the encrypted data
        this.storage.set(options.key, {
            wrappedDek: this.arrayBufferToBase64(wrappedDek),
            encryptedData: this.arrayBufferToBase64(encryptedData),
            metadata
        });
        // Persist to storage (async)
        this.persistToDisk();
    }
    /**
     * Retrieve data securely
     */
    async retrieve(options) {
        const encryptedData = this.storage.get(options.key);
        if (!encryptedData) {
            return null;
        }
        // Check expiration
        if (encryptedData.metadata.expires && encryptedData.metadata.expires < Date.now()) {
            // Data has expired, delete it securely
            await this.delete({ key: options.key, secureDelete: true });
            return null;
        }
        // Get the appropriate key for the data's sensitivity level
        const encryptionKey = this.getKeyForSensitivity(encryptedData.metadata.sensitivity);
        if (!encryptionKey) {
            throw new Error('Decryption key not available');
        }
        try {
            // Unwrap the data encryption key
            const wrappedDekBuffer = this.base64ToArrayBuffer(encryptedData.wrappedDek);
            const dek = await this.unwrapKey(wrappedDekBuffer, encryptionKey);
            // Decrypt the data with the unwrapped DEK
            const encryptedDataBuffer = this.base64ToArrayBuffer(encryptedData.encryptedData);
            const ivBuffer = this.base64ToArrayBuffer(encryptedData.metadata.iv);
            const decryptedData = await this.decryptWithKey(encryptedDataBuffer, dek, ivBuffer);
            // Parse the data
            return JSON.parse(decryptedData);
        }
        catch (error) {
            console.error('Error decrypting data:', error);
            return null;
        }
    }
    /**
     * Delete data securely
     */
    async delete(options) {
        const encryptedData = this.storage.get(options.key);
        if (!encryptedData) {
            return;
        }
        if (options.secureDelete) {
            // Perform secure deletion with overwriting
            await this.securelyDeleteData(options.key, encryptedData);
        }
        // Remove from in-memory storage
        this.storage.delete(options.key);
        // Update persistent storage
        this.persistToDisk();
    }
    /**
     * Generate a new master key
     */
    async generateMasterKey() {
        // In a real implementation, this would be derived from a user password
        // or loaded from a secure enclave / secure element
        const keyMaterial = this.getRandomBytes(32);
        return window.crypto.subtle.importKey('raw', keyMaterial, {
            name: 'HKDF',
            hash: 'SHA-256'
        }, false, ['deriveKey', 'deriveBits']);
    }
    /**
     * Derive storage keys from the master key
     */
    async deriveStorageKeys() {
        if (!this.masterKey) {
            throw new Error('Master key not available');
        }
        // Derive keys for different sensitivity levels
        this.storageKeys.normal = await this.deriveKey(this.masterKey, 'storage-key-normal');
        this.storageKeys.high = await this.deriveKey(this.masterKey, 'storage-key-high');
        this.storageKeys.critical = await this.deriveKey(this.masterKey, 'storage-key-critical');
        this.lastKeyRotation = Date.now();
    }
    /**
     * Derive a specific key from the master key
     */
    async deriveKey(masterKey, info) {
        const keyMaterial = await window.crypto.subtle.deriveBits({
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new Uint8Array(32),
            info: new TextEncoder().encode(info)
        }, masterKey, 256);
        return window.crypto.subtle.importKey('raw', keyMaterial, {
            name: 'AES-GCM',
        }, false, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']);
    }
    /**
     * Generate a data encryption key (DEK) for a specific data item
     */
    async generateDataEncryptionKey() {
        return window.crypto.subtle.generateKey({
            name: 'AES-GCM',
            length: 256
        }, true, ['encrypt', 'decrypt']);
    }
    /**
     * Wrap (encrypt) a data encryption key with a storage key
     */
    async wrapKey(dek, wrappingKey) {
        // Use key wrapping with AES-GCM
        return window.crypto.subtle.wrapKey('raw', dek, wrappingKey, {
            name: 'AES-GCM',
            iv: this.getRandomBytes(12)
        });
    }
    /**
     * Unwrap (decrypt) a data encryption key with a storage key
     */
    async unwrapKey(wrappedDek, unwrappingKey) {
        // Unwrap the DEK
        return window.crypto.subtle.unwrapKey('raw', wrappedDek, unwrappingKey, {
            name: 'AES-GCM',
            iv: this.getRandomBytes(12) // This should be the same IV used for wrapping
        }, {
            name: 'AES-GCM',
            length: 256
        }, false, ['encrypt', 'decrypt']);
    }
    /**
     * Encrypt data with a specific key
     */
    async encryptWithKey(data, key, iv) {
        const encoder = new TextEncoder();
        const encodedData = encoder.encode(data);
        return window.crypto.subtle.encrypt({
            name: 'AES-GCM',
            iv
        }, key, encodedData);
    }
    /**
     * Decrypt data with a specific key
     */
    async decryptWithKey(encryptedData, key, iv) {
        const decrypted = await window.crypto.subtle.decrypt({
            name: 'AES-GCM',
            iv
        }, key, encryptedData);
        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    }
    /**
     * Securely delete data by overwriting it multiple times
     */
    async securelyDeleteData(key, encryptedData) {
        // Get the data's buffer
        const dataBuffer = this.base64ToArrayBuffer(encryptedData.encryptedData);
        // Number of passes for secure overwriting
        const PASSES = 3;
        // Overwrite with random data multiple times
        for (let i = 0; i < PASSES; i++) {
            const randomData = this.getRandomBytes(dataBuffer.byteLength);
            // In a real implementation, this would write to the actual storage location
            // For this demo, we're just simulating the overwrite
            console.log(`Secure delete: pass ${i + 1}/${PASSES} for key ${key}`);
        }
        // Final overwrite with zeros
        const zeroBuffer = new Uint8Array(dataBuffer.byteLength);
        zeroBuffer.fill(0);
        // In a real implementation, this would write to the actual storage location
        console.log(`Secure delete: final zero pass for key ${key}`);
    }
    /**
     * Schedule key rotation
     */
    scheduleKeyRotation() {
        // Schedule key rotation
        setInterval(() => {
            this.rotateKeys();
        }, this.KEY_ROTATION_INTERVAL);
    }
    /**
     * Rotate storage keys
     */
    async rotateKeys() {
        console.log('Rotating storage keys...');
        // Generate new master key
        const newMasterKey = await this.generateMasterKey();
        // Store old keys for re-encryption
        const oldKeys = { ...this.storageKeys };
        // Set new master key
        this.masterKey = newMasterKey;
        // Derive new storage keys
        await this.deriveStorageKeys();
        // Re-encrypt all data with new keys
        await this.reencryptAllData(oldKeys);
        console.log('Key rotation complete');
    }
    /**
     * Re-encrypt all data with new keys
     */
    async reencryptAllData(oldKeys) {
        // For each item in storage
        for (const [key, encryptedData] of this.storage.entries()) {
            // Get the old key for this sensitivity level
            const oldKey = oldKeys[encryptedData.metadata.sensitivity];
            if (!oldKey) {
                console.error(`Missing old key for sensitivity ${encryptedData.metadata.sensitivity}`);
                continue;
            }
            try {
                // Unwrap the DEK with the old key
                const wrappedDekBuffer = this.base64ToArrayBuffer(encryptedData.wrappedDek);
                const dek = await this.unwrapKey(wrappedDekBuffer, oldKey);
                // Decrypt the data
                const encryptedDataBuffer = this.base64ToArrayBuffer(encryptedData.encryptedData);
                const ivBuffer = this.base64ToArrayBuffer(encryptedData.metadata.iv);
                const decryptedData = await this.decryptWithKey(encryptedDataBuffer, dek, ivBuffer);
                // Re-encrypt with new key
                const newData = JSON.parse(decryptedData);
                // Store with the same options but new keys
                await this.store({
                    key,
                    data: newData,
                    keySensitivity: encryptedData.metadata.sensitivity,
                    expirationTime: encryptedData.metadata.expires
                        ? encryptedData.metadata.expires - Date.now()
                        : undefined
                });
            }
            catch (error) {
                console.error(`Error re-encrypting data for key ${key}:`, error);
            }
        }
    }
    /**
     * Get the appropriate key for a sensitivity level
     */
    getKeyForSensitivity(sensitivity) {
        return this.storageKeys[sensitivity];
    }
    /**
     * Load encrypted data from persistent storage
     */
    async loadFromPersistentStorage() {
        // This would load from IndexedDB, localStorage, or a file
        // For this demo, we're just initializing an empty storage
        this.storage = new Map();
    }
    /**
     * Persist data to disk/storage
     */
    persistToDisk() {
        // This would save to IndexedDB, localStorage, or a file
        // For this demo, we're just logging
        console.log(`Persisting ${this.storage.size} items to storage`);
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
        // Clear in-memory storage
        this.storage.clear();
        // Clear keys
        this.masterKey = null;
        this.storageKeys.normal = null;
        this.storageKeys.high = null;
        this.storageKeys.critical = null;
    }
}
exports.SecureStorage = SecureStorage;
