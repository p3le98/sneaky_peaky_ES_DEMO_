/**
 * @fileoverview Direct Transport
 * 
 * Simple direct messaging implementation for point-to-point communication.
 * Provides a lightweight, low-latency transport mechanism for direct connections.
 * 
 * Security Controls:
 * - NIST 800-53 SC-8: Transmission Confidentiality
 * - NIST 800-53 SC-13: Cryptographic Protection
 */

import { EventEmitter } from 'events';

/**
 * Direct messaging configuration
 */
export interface DirectTransportConfig {
  /** Server URL for WebSocket connection */
  serverUrl: string;
  /** Connection timeout in milliseconds */
  connectionTimeout?: number;
  /** Enable message encryption */
  encryption?: boolean;
  /** Client ID for stable identification */
  clientId: string;
  /** Retry configuration */
  retry?: {
    /** Maximum retry attempts */
    maxAttempts: number;
    /** Base delay between retries (ms) */
    baseDelay: number;
    /** Maximum delay between retries (ms) */
    maxDelay: number;
  };
}

/**
 * Message envelope for direct messaging
 */
export interface DirectMessage {
  /** Message ID */
  id: string;
  /** Recipient ID */
  recipientId: string;
  /** Sender ID */
  senderId: string;
  /** Message content */
  content: string | Uint8Array;
  /** Message timestamp */
  timestamp: number;
  /** Optional metadata */
  metadata?: Record<string, any>;
}

/**
 * Connection status
 */
export enum ConnectionStatus {
  DISCONNECTED = 'disconnected',
  CONNECTING = 'connecting',
  CONNECTED = 'connected',
  RECONNECTING = 'reconnecting',
  ERROR = 'error'
}

/**
 * Event types for DirectTransport
 */
export interface DirectTransportEvents {
  message: (message: DirectMessage) => void;
  status_change: (status: ConnectionStatus) => void;
  reconnect_failed: () => void;
}

/**
 * Direct Transport implementation
 * Provides simple direct messaging functionality
 */
export class DirectTransport extends EventEmitter {
  private socket: WebSocket | null = null;
  private status: ConnectionStatus = ConnectionStatus.DISCONNECTED;
  private messageQueue: DirectMessage[] = [];
  private retryCount: number = 0;
  private retryTimer: any = null;
  private connectionTimeout: any = null;
  private messageHandlers: Map<string, ((message: DirectMessage) => void)[]> = new Map();
  private pendingMessages: Map<string, { resolve: Function, reject: Function }> = new Map();
  private encryptionKey: CryptoKey | null = null;
  
  /**
   * Creates a new DirectTransport instance
   * @param config Transport configuration
   */
  constructor(private config: DirectTransportConfig) {
    super();
    
    // Set default values
    this.config.connectionTimeout = this.config.connectionTimeout || 10000;
    this.config.retry = this.config.retry || {
      maxAttempts: 5,
      baseDelay: 1000,
      maxDelay: 30000
    };
    this.config.encryption = this.config.encryption !== false;
    
    // Initialize encryption key
    if (this.config.encryption) {
      this.initializeEncryptionKey();
    }
  }
  
  private async initializeEncryptionKey(): Promise<void> {
    // In a real implementation, this key would be shared securely between clients
    // For demo purposes, we're using a hardcoded key
    const rawKey = new Uint8Array(32); // 256-bit key
    crypto.getRandomValues(rawKey);
    
    this.encryptionKey = await crypto.subtle.importKey(
      'raw',
      rawKey,
      'AES-GCM',
      false,
      ['encrypt', 'decrypt']
    );
  }
  
  private async encryptMessage(message: DirectMessage): Promise<DirectMessage> {
    if (!this.encryptionKey) {
      throw new Error('Encryption key not initialized');
    }

    const encoder = new TextEncoder();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      this.encryptionKey,
      encoder.encode(message.content as string)
    );

    return {
      ...message,
      content: this.arrayBufferToHex(iv) + '.' + this.arrayBufferToHex(ciphertext),
      metadata: { ...message.metadata, encrypted: true }
    };
  }
  
  private async decryptMessage(message: DirectMessage): Promise<DirectMessage> {
    if (!this.encryptionKey || !message.metadata?.encrypted) {
      return message;
    }

    const [ivHex, ciphertextHex] = (message.content as string).split('.');
    const iv = this.hexToArrayBuffer(ivHex);
    const ciphertext = this.hexToArrayBuffer(ciphertextHex);

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      this.encryptionKey,
      ciphertext
    );

    return {
      ...message,
      content: new TextDecoder().decode(decrypted),
      metadata: { ...message.metadata, encrypted: false }
    };
  }
  
  /**
   * Convert ArrayBuffer to hex string (browser-compatible)
   */
  private arrayBufferToHex(buffer: ArrayBuffer): string {
    const uint8Array = new Uint8Array(buffer);
    return Array.from(uint8Array)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Convert hex string to ArrayBuffer (browser-compatible)
   */
  private hexToArrayBuffer(hex: string): ArrayBuffer {
    const uint8Array = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      uint8Array[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return uint8Array.buffer;
  }
  
  /**
   * Initialize the transport
   */
  async initialize(): Promise<void> {
    await this.connect();
  }
  
  /**
   * Connect to the direct messaging server
   */
  async connect(): Promise<void> {
    if (this.status === ConnectionStatus.CONNECTING || 
        this.status === ConnectionStatus.CONNECTED) {
      return;
    }
    
    this.setStatus(ConnectionStatus.CONNECTING);
    
    try {
      await this.establishConnection();
    } catch (error) {
      this.setStatus(ConnectionStatus.ERROR);
      this.scheduleReconnect();
      throw error;
    }
  }
  
  /**
   * Establish WebSocket connection
   */
  private async establishConnection(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.socket = new WebSocket(this.config.serverUrl);
      
      // Set connection timeout
      this.connectionTimeout = setTimeout(() => {
        if (this.status !== ConnectionStatus.CONNECTED) {
          const error = new Error(`Connection timeout after ${this.config.connectionTimeout}ms`);
          this.handleConnectionError(error);
          reject(error);
        }
      }, this.config.connectionTimeout);
      
      this.socket.onopen = () => {
        clearTimeout(this.connectionTimeout);
        this.setStatus(ConnectionStatus.CONNECTED);
        this.retryCount = 0;
        this.processQueue();
        resolve();
      };
      
      this.socket.onclose = () => {
        this.handleDisconnect();
      };
      
      this.socket.onerror = (event) => {
        const error = new Error('WebSocket connection error');
        this.handleConnectionError(error);
        reject(error);
      };
      
      this.socket.onmessage = (event) => {
        this.handleIncomingMessage(event);
      };
    });
  }
  
  /**
   * Handle incoming WebSocket message
   */
  private async handleIncomingMessage(event: MessageEvent): Promise<void> {
    try {
      const message = JSON.parse(event.data) as DirectMessage;
      
      // Verify message structure
      if (!message.id || !message.senderId || !message.content) {
        console.warn('Received malformed message:', message);
        return;
      }
      
      // Decrypt message if encrypted
      const decryptedMessage = await this.decryptMessage(message);
      
      // Emit message event
      this.emit('message', decryptedMessage);
      
      // Call specific handlers for this recipient
      const handlers = this.messageHandlers.get(decryptedMessage.recipientId);
      if (handlers) {
        handlers.forEach(handler => handler(decryptedMessage));
      }
      
      // Resolve pending message if it's an acknowledgment
      if (decryptedMessage.metadata?.ack) {
        const pending = this.pendingMessages.get(decryptedMessage.metadata.ack);
        if (pending) {
          pending.resolve({ success: true, messageId: decryptedMessage.id });
          this.pendingMessages.delete(decryptedMessage.metadata.ack);
        }
      }
    } catch (error) {
      console.error('Error processing incoming message:', error);
    }
  }
  
  /**
   * Handle connection error
   */
  private handleConnectionError(error: Error): void {
    clearTimeout(this.connectionTimeout);
    console.error('DirectTransport connection error:', error);
    this.setStatus(ConnectionStatus.ERROR);
    this.scheduleReconnect();
  }
  
  /**
   * Handle disconnection
   */
  private handleDisconnect(): void {
    if (this.status === ConnectionStatus.CONNECTED) {
      this.setStatus(ConnectionStatus.DISCONNECTED);
      this.scheduleReconnect();
    }
  }
  
  /**
   * Schedule a reconnection attempt
   */
  private scheduleReconnect(): void {
    if (this.retryTimer) {
      clearTimeout(this.retryTimer);
    }
    
    if (this.retryCount >= this.config.retry!.maxAttempts) {
      this.emit('reconnect_failed');
      return;
    }
    
    this.retryCount++;
    this.setStatus(ConnectionStatus.RECONNECTING);
    
    // Calculate exponential backoff with jitter
    const delay = Math.min(
      this.config.retry!.baseDelay * Math.pow(2, this.retryCount - 1),
      this.config.retry!.maxDelay
    ) * (0.75 + Math.random() * 0.5); // Add 25% jitter
    
    this.retryTimer = setTimeout(() => {
      this.connect().catch(() => {
        // Error will be handled by connect
      });
    }, delay);
  }
  
  /**
   * Update connection status
   */
  private setStatus(status: ConnectionStatus): void {
    if (this.status !== status) {
      this.status = status;
      this.emit('status_change', status);
    }
  }
  
  /**
   * Get current connection status
   */
  getStatus(): ConnectionStatus {
    return this.status;
  }
  
  /**
   * Send a message to a recipient
   * @param recipientId Recipient ID
   * @param content Message content
   * @param metadata Optional metadata
   */
  async sendMessage(
    recipientId: string, 
    content: string | Uint8Array, 
    metadata?: Record<string, any>
  ): Promise<{ success: boolean, messageId?: string, error?: string }> {
    // Generate unique message ID
    const messageId = this.generateId();
    
    // Create message object
    const message: DirectMessage = {
      id: messageId,
      recipientId,
      senderId: this.getClientId(),
      content,
      timestamp: Date.now(),
      metadata
    };
    
    // Encrypt message if enabled
    const preparedMessage = this.config.encryption ? 
      await this.encryptMessage(message) : 
      message;
    
    // If connected, send immediately; otherwise queue
    if (this.status === ConnectionStatus.CONNECTED && this.socket?.readyState === WebSocket.OPEN) {
      return this.sendDirectMessage(preparedMessage);
    } else {
      this.messageQueue.push(preparedMessage);
      
      // Auto-connect if disconnected
      if (this.status === ConnectionStatus.DISCONNECTED) {
        this.connect().catch(error => {
          console.error('Failed to connect for sending message:', error);
        });
      }
      
      // Return a promise that resolves when message is sent
      return new Promise((resolve, reject) => {
        this.pendingMessages.set(messageId, { resolve, reject });
        
        // Set timeout for pending message
        setTimeout(() => {
          if (this.pendingMessages.has(messageId)) {
            this.pendingMessages.delete(messageId);
            reject({ success: false, error: 'Message sending timed out' });
          }
        }, 30000); // 30 second timeout
      });
    }
  }
  
  /**
   * Actually send a message over the socket
   */
  private async sendDirectMessage(message: DirectMessage): Promise<{ success: boolean, messageId?: string, error?: string }> {
    return new Promise((resolve, reject) => {
      try {
        this.socket!.send(JSON.stringify(message));
        
        // Store pending message for acknowledgment
        this.pendingMessages.set(message.id, { resolve, reject });
        
        // Set timeout for pending message
        setTimeout(() => {
          if (this.pendingMessages.has(message.id)) {
            this.pendingMessages.delete(message.id);
            resolve({ 
              success: true, 
              messageId: message.id,
              error: 'No acknowledgment received, but message was sent'
            });
          }
        }, 5000); // 5 second timeout for acknowledgment
      } catch (error) {
        console.error('Error sending message:', error);
        this.messageQueue.push(message);
        reject({ 
          success: false, 
          error: error instanceof Error ? error.message : 'Unknown error sending message'
        });
      }
    });
  }
  
  /**
   * Process queued messages
   */
  private processQueue(): void {
    if (this.status !== ConnectionStatus.CONNECTED || !this.socket || this.socket.readyState !== WebSocket.OPEN) {
      return;
    }
    
    while (this.messageQueue.length > 0) {
      const message = this.messageQueue.shift();
      if (message) {
        this.sendDirectMessage(message).catch(error => {
          console.error('Failed to send queued message:', error);
          // Push back to queue on failure
          this.messageQueue.unshift(message);
        });
      }
    }
  }
  
  /**
   * Register a message handler for a specific recipient
   * @param recipientId Recipient ID to listen for
   * @param handler Message handler function
   */
  onMessage(recipientId: string, handler: (message: DirectMessage) => void): void {
    if (!this.messageHandlers.has(recipientId)) {
      this.messageHandlers.set(recipientId, []);
    }
    this.messageHandlers.get(recipientId)!.push(handler);
  }
  
  /**
   * Unregister a message handler
   * @param recipientId Recipient ID
   * @param handler Handler to remove (or all if not specified)
   */
  offMessage(recipientId: string, handler?: (message: DirectMessage) => void): void {
    if (!handler) {
      this.messageHandlers.delete(recipientId);
    } else {
      const handlers = this.messageHandlers.get(recipientId);
      if (handlers) {
        const index = handlers.indexOf(handler);
        if (index !== -1) {
          handlers.splice(index, 1);
        }
        if (handlers.length === 0) {
          this.messageHandlers.delete(recipientId);
        }
      }
    }
  }
  
  /**
   * Close the connection
   */
  async disconnect(): Promise<void> {
    if (this.retryTimer) {
      clearTimeout(this.retryTimer);
    }
    
    if (this.connectionTimeout) {
      clearTimeout(this.connectionTimeout);
    }
    
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
    
    this.setStatus(ConnectionStatus.DISCONNECTED);
  }
  
  /**
   * Generate a unique ID
   */
  private generateId(): string {
    return Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
  }
  
  /**
   * Get client ID (simple implementation)
   */
  private getClientId(): string {
    return this.config.clientId;
  }
  
  // Type-safe event emit/on methods
  emit(event: 'message', message: DirectMessage): boolean;
  emit(event: 'status_change', status: ConnectionStatus): boolean;
  emit(event: 'reconnect_failed'): boolean;
  emit(event: string | symbol, ...args: any[]): boolean {
    return super.emit(event, ...args);
  }
  
  on(event: 'message', listener: (message: DirectMessage) => void): this;
  on(event: 'status_change', listener: (status: ConnectionStatus) => void): this;
  on(event: 'reconnect_failed', listener: () => void): this;
  on(event: string | symbol, listener: (...args: any[]) => void): this {
    return super.on(event, listener);
  }
} 