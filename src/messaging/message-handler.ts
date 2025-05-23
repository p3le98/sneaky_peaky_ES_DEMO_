import { RatchetSessionManager } from '../crypto/ratchet-session-manager';
import { SecureStorage } from '../crypto/secure-storage';
import { MessageValidator, ValidationResult } from '../validation';
import { Message, MessageDeliveryStatus } from './message-types';

export interface IncomingMessage {
  id: string;
  sender: string;
  content: Uint8Array;
  metadata: Record<string, any>;
  timestamp: number;
  protocol: string;
}

export interface MessageHandlerConfig {
  autoDecrypt: boolean;
  validateSender: boolean;
  storeMessages: boolean;
  maxStoredMessages: number;
}

export interface MessageProcessResult {
  success: boolean;
  messageId: string;
  decrypted: boolean;
  validated: boolean;
  error?: string;
}

interface SessionState {
  peerId: string;
  isInitiator: boolean;
  lastKeyRotation: number;
  messageCount: number;
  lastActivity: number;
}

export class MessageHandler {
  private messageStore: Map<string, IncomingMessage> = new Map();
  private config: MessageHandlerConfig = {
    autoDecrypt: true,
    validateSender: true,
    storeMessages: true,
    maxStoredMessages: 1000
  };
  
  private messageCallbacks: Array<(message: IncomingMessage) => void> = [];
  private ratchetManager: RatchetSessionManager;
  private keyRotationInterval: number = 24 * 60 * 60 * 1000; // 24 hours
  private keyRotationTimers: Map<string, ReturnType<typeof setTimeout>> = new Map();
  private sessionStates: Map<string, SessionState> = new Map();
  private deliveryStatusCallbacks: Array<(messageId: string, status: MessageDeliveryStatus) => void> = [];

  constructor(
    private storage: SecureStorage,
    private messageValidator: MessageValidator,
    config?: Partial<MessageHandlerConfig>
  ) {
    if (config) {
      this.config = { ...this.config, ...config };
    }
    this.ratchetManager = new RatchetSessionManager(storage);
  }
  
  /**
   * Initialize a new chat session with Double Ratchet
   */
  async initializeChat(chatId: string, peerId: string, isInitiator: boolean): Promise<void> {
    try {
      // Initialize Double Ratchet session
      await this.ratchetManager.initializeSession(chatId, peerId, isInitiator);
      
      // Initialize session state
      this.sessionStates.set(chatId, {
        peerId,
        isInitiator,
        lastKeyRotation: Date.now(),
        messageCount: 0,
        lastActivity: Date.now()
      });

      // Set up key rotation
      this.scheduleKeyRotation(chatId);
    } catch (error) {
      throw new Error(`Failed to initialize chat: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  
  private scheduleKeyRotation(chatId: string): void {
    // Clear existing timer if any
    const existingTimer = this.keyRotationTimers.get(chatId);
    if (existingTimer) {
      clearTimeout(existingTimer);
    }

    // Schedule new key rotation
    const timer = setTimeout(async () => {
      try {
        await this.rotateKeys(chatId);
        this.scheduleKeyRotation(chatId); // Schedule next rotation
      } catch (error) {
        console.error(`Key rotation failed for chat ${chatId}:`, error);
      }
    }, this.keyRotationInterval);

    this.keyRotationTimers.set(chatId, timer);
  }

  /**
   * Rotate encryption keys for a chat session
   */
  async rotateKeys(chatId: string): Promise<void> {
    const sessionState = this.sessionStates.get(chatId);
    if (!sessionState) {
      throw new Error(`No session state found for chat ${chatId}`);
    }

    try {
      // Rotate keys in Double Ratchet
      await this.ratchetManager.initializeSession(chatId, sessionState.peerId, sessionState.isInitiator);

      // Update session state
      sessionState.lastKeyRotation = Date.now();
      this.sessionStates.set(chatId, sessionState);

      // Notify about key rotation
      const rotationMessage = {
        type: 'key_rotation',
        chatId,
        timestamp: Date.now()
      };

      // Send key rotation notification
      // Note: This should be implemented in your transport layer
      // await this.transport.sendMessage(chatId, rotationMessage);
    } catch (error) {
      throw new Error(`Key rotation failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  
  async handleIncomingMessage(rawMessage: any): Promise<MessageProcessResult> {
    try {
      // Basic validation of incoming message structure
      if (!rawMessage || !rawMessage.sender || !rawMessage.content || !rawMessage.chatId) {
        return {
          success: false,
          messageId: rawMessage?.id || 'unknown',
          decrypted: false,
          validated: false,
          error: 'Invalid message format'
        };
      }
      
      // Update session state
      const sessionState = this.sessionStates.get(rawMessage.chatId);
      if (sessionState) {
        sessionState.messageCount++;
        sessionState.lastActivity = Date.now();
        this.sessionStates.set(rawMessage.chatId, sessionState);
      }
      
      // Create standard message object
      const message: IncomingMessage = {
        id: rawMessage.id || `msg_${Date.now()}`,
        sender: rawMessage.sender,
        content: rawMessage.content,
        metadata: rawMessage.metadata || {},
        timestamp: rawMessage.timestamp || Date.now(),
        protocol: rawMessage.protocol || 'unknown'
      };
      
      let decrypted = false;
      let validated = false;
      
      // Decrypt using Double Ratchet
      if (this.config.autoDecrypt) {
        try {
          message.content = await this.ratchetManager.decryptMessage(
            rawMessage.chatId,
            rawMessage.sender,
            message.content
          );
          decrypted = true;
        } catch (error) {
          return {
            success: false,
            messageId: message.id,
            decrypted: false,
            validated: false,
            error: 'Decryption failed: ' + (error instanceof Error ? error.message : String(error))
          };
        }
      }
      
      // Validate message and sender
      if (this.config.validateSender) {
        const validationResult = await this.validateMessage(message);
        if (!validationResult) {
          return {
            success: false,
            messageId: message.id,
            decrypted,
            validated: false,
            error: 'Message validation failed'
          };
        }
        validated = true;
      } else {
        validated = true; // Skip validation if not required
      }
      
      // Store message if configured to do so
      if (this.config.storeMessages) {
        this.storeMessage(message);
      }
      
      // Notify listeners
      this.notifyListeners(message);
      
      // Notify about delivery status
      this.notifyDeliveryStatus(message.id, MessageDeliveryStatus.DELIVERED);
      
      return {
        success: true,
        messageId: message.id,
        decrypted,
        validated
      };
    } catch (error) {
      return {
        success: false,
        messageId: 'unknown',
        decrypted: false,
        validated: false,
        error: 'Error processing message: ' + (error instanceof Error ? error.message : String(error))
      };
    }
  }

  /**
   * Send a message using Double Ratchet encryption
   */
  async sendMessage(chatId: string, peerId: string, content: Uint8Array): Promise<Uint8Array> {
    try {
      const encryptedContent = await this.ratchetManager.encryptMessage(chatId, peerId, content);
      
      // IMPLEMENTATION: Return the encrypted content so it can be sent by the transport layer
      return encryptedContent;
    } catch (error) {
      throw new Error(`Failed to encrypt message: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  
  private async validateMessage(message: IncomingMessage): Promise<boolean> {
    if (!message || typeof message !== 'object') {
      return false;
    }

    if (!message.sender || !message.content) {
      return false;
    }

    if (message.content instanceof Uint8Array && message.content.length > 1000000) {
      return false;
    }

    return true;
  }
  
  private storeMessage(message: IncomingMessage): void {
    // Check if we need to remove older messages to stay under limit
    if (this.messageStore.size >= this.config.maxStoredMessages) {
      // Find oldest message
      let oldestId: string | null = null;
      let oldestTimestamp = Infinity;
      
      for (const [id, msg] of this.messageStore.entries()) {
        if (msg.timestamp < oldestTimestamp) {
          oldestId = id;
          oldestTimestamp = msg.timestamp;
        }
      }
      
      // Remove oldest message
      if (oldestId) {
        this.messageStore.delete(oldestId);
      }
    }
    
    // Store the new message
    this.messageStore.set(message.id, message);
  }
  
  getStoredMessages(): IncomingMessage[] {
    return Array.from(this.messageStore.values());
  }
  
  getMessageById(id: string): IncomingMessage | undefined {
    return this.messageStore.get(id);
  }
  
  clearMessageStore(): void {
    this.messageStore.clear();
  }
  
  private notifyListeners(message: IncomingMessage): void {
    for (const callback of this.messageCallbacks) {
      callback(message);
    }
  }
  
  onMessage(callback: (message: IncomingMessage) => void): void {
    this.messageCallbacks.push(callback);
  }

  async cleanup(): Promise<void> {
    // Clear all key rotation timers
    for (const timer of this.keyRotationTimers.values()) {
      clearTimeout(timer);
    }
    this.keyRotationTimers.clear();

    // Clear session states
    this.sessionStates.clear();

    // Clear message store
    this.messageStore.clear();
  }

  /**
   * Subscribe to message delivery status updates
   */
  onDeliveryStatus(callback: (messageId: string, status: MessageDeliveryStatus) => void): void {
    this.deliveryStatusCallbacks.push(callback);
  }

  private notifyDeliveryStatus(messageId: string, status: MessageDeliveryStatus): void {
    for (const callback of this.deliveryStatusCallbacks) {
      callback(messageId, status);
    }
  }
} 