import { v4 as uuidv4 } from 'uuid';
import { SecurityLevel, MessagePriority } from '../routing/smart-routing-manager';
import { Message, MessageMetadata, SecurityFlags } from './message-types';

/**
 * Message Factory - Creates standardized message formats
 * with proper security properties
 */
export class MessageFactory {
  /**
   * Creates a new message with standardized format
   * 
   * @param content The message content
   * @param sender The sender ID
   * @param recipient The recipient ID
   * @param options Additional message options
   * @returns A new standardized message
   */
  createMessage(
    content: string,
    sender: string,
    recipient: string,
    options: {
      priority?: MessagePriority;
      securityLevel?: SecurityLevel;
      metadata?: Partial<MessageMetadata>;
      securityFlags?: SecurityFlags;
    } = {}
  ): Message {
    const now = Date.now();
    const id = uuidv4();
    
    // Set default TTL based on security level
    let ttl = 86400000; // 24 hours by default
    if (options.securityLevel === SecurityLevel.MAXIMUM) {
      ttl = 3600000; // 1 hour for maximum security
    } else if (options.securityLevel === SecurityLevel.HIGH) {
      ttl = 43200000; // 12 hours for high security
    }
    
    const metadata: MessageMetadata = {
      ...(options.metadata || {}),
      securityFlags: options.securityFlags || {},
      ttl: options.metadata?.ttl || ttl,
      expiresAt: now + (options.metadata?.ttl || ttl)
    };
    
    // Apply security rules based on security level
    if (options.securityLevel === SecurityLevel.MAXIMUM) {
      if (!metadata.securityFlags) {
        metadata.securityFlags = {};
      }
      metadata.securityFlags.ephemeral = true;
      metadata.securityFlags.forwardingDisabled = true;
      metadata.securityFlags.screenshotDisabled = true;
    }
    
    return {
      id,
      content,
      sender,
      recipient,
      timestamp: now,
      priority: options.priority || MessagePriority.NORMAL,
      securityLevel: options.securityLevel || SecurityLevel.STANDARD,
      metadata
    };
  }
  
  /**
   * Creates a system message (from the system to a user)
   * 
   * @param content The message content
   * @param recipient The recipient ID
   * @param options Additional message options
   * @returns A new system message
   */
  createSystemMessage(
    content: string,
    recipient: string,
    options: {
      priority?: MessagePriority;
      securityLevel?: SecurityLevel;
      metadata?: Partial<MessageMetadata>;
    } = {}
  ): Message {
    return this.createMessage(
      content,
      'system',
      recipient,
      {
        priority: options.priority || MessagePriority.HIGH,
        securityLevel: options.securityLevel || SecurityLevel.STANDARD,
        metadata: {
          ...(options.metadata || {}),
          isSystemMessage: true
        }
      }
    );
  }
  
  /**
   * Creates an ephemeral message that will be automatically deleted
   * 
   * @param content The message content
   * @param sender The sender ID
   * @param recipient The recipient ID
   * @param ttl Time to live in milliseconds
   * @param options Additional message options
   * @returns A new ephemeral message
   */
  createEphemeralMessage(
    content: string,
    sender: string,
    recipient: string,
    ttl: number = 300000, // Default 5 minutes
    options: {
      priority?: MessagePriority;
      securityLevel?: SecurityLevel;
      metadata?: Partial<MessageMetadata>;
    } = {}
  ): Message {
    return this.createMessage(
      content,
      sender,
      recipient,
      {
        priority: options.priority || MessagePriority.NORMAL,
        securityLevel: options.securityLevel || SecurityLevel.HIGH,
        metadata: {
          ...(options.metadata || {}),
          ttl,
          expiresAt: Date.now() + ttl
        },
        securityFlags: {
          ephemeral: true,
          forwardingDisabled: true,
          screenshotDisabled: true
        }
      }
    );
  }
  
  /**
   * Creates a reply to an existing message
   * 
   * @param originalMessageId The ID of the message being replied to
   * @param content The reply content
   * @param sender The sender ID
   * @param recipient The recipient ID
   * @param options Additional message options
   * @returns A new reply message
   */
  createReplyMessage(
    originalMessageId: string,
    content: string,
    sender: string,
    recipient: string,
    options: {
      priority?: MessagePriority;
      securityLevel?: SecurityLevel;
      metadata?: Partial<MessageMetadata>;
    } = {}
  ): Message {
    return this.createMessage(
      content,
      sender,
      recipient,
      {
        priority: options.priority || MessagePriority.NORMAL,
        securityLevel: options.securityLevel || SecurityLevel.STANDARD,
        metadata: {
          ...(options.metadata || {}),
          replyToId: originalMessageId
        }
      }
    );
  }
  
  /**
   * Creates a group message to be sent to multiple recipients
   * 
   * @param content The message content
   * @param sender The sender ID
   * @param conversationId The group conversation ID
   * @param options Additional message options
   * @returns A group message
   */
  createGroupMessage(
    content: string,
    sender: string,
    conversationId: string,
    options: {
      priority?: MessagePriority;
      securityLevel?: SecurityLevel;
      metadata?: Partial<MessageMetadata>;
    } = {}
  ): Message {
    return this.createMessage(
      content,
      sender,
      conversationId,
      {
        priority: options.priority || MessagePriority.NORMAL,
        securityLevel: options.securityLevel || SecurityLevel.STANDARD,
        metadata: {
          ...(options.metadata || {}),
          conversationId,
          isGroupMessage: true
        }
      }
    );
  }
} 