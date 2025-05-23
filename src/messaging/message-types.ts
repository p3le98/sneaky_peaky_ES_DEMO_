/**
 * @file message-types.ts
 * @description Core data types for the Sneaky Peaky Chat messaging system.
 * 
 * This file defines the central data structures and types used throughout the messaging system.
 * It provides a single source of truth for message-related interfaces to ensure consistency
 * across the application.
 * 
 * The messaging system architecture follows these principles:
 * 1. End-to-end encryption for all messages
 * 2. Multiple security tiers (Essential, Enhanced, Maximum)
 * 3. Support for both direct and group messaging
 * 4. Message metadata protection
 * 5. Flexible message routing through different transport channels
 * 6. Offline message handling with prioritization
 * 
 * Security features include:
 * - Post-quantum cryptography integration
 * - Forward secrecy with key rotation
 * - Metadata obfuscation for higher security tiers
 * - Secure message deletion and ephemeral messages
 * - Protection against traffic analysis
 */

import { MessagePriority } from './secure-message-handler';
import { SecurityLevel } from '../core/security-levels';

/**
 * Core message type representing a message in the system
 */
export interface Message {
  id: string;
  chatId: string;
  senderId: string;
  recipient: string;
  content: Uint8Array;
  timestamp: number;
  priority: MessagePriority;
  securityLevel: SecurityLevel;
  size: number;
  metadata: MessageMetadata;
}

/**
 * Metadata associated with messages
 */
export interface MessageMetadata {
  conversationId?: string;
  replyToId?: string;
  deliveryStatus?: MessageDeliveryStatus;
  deliveryTimestamp?: number;
  readTimestamp?: number;
  expiresAt?: number;
  ttl?: number; // Time to live in milliseconds
  securityFlags?: SecurityFlags;
  transportInfo?: TransportInfo;
  applicationData?: Record<string, any>;
  
  // Metadata protection fields
  protectionApplied?: boolean;
  encryptedTimestamps?: Uint8Array;
  encryptedParticipants?: Uint8Array;
  noiseData?: Uint8Array;
  padding?: Uint8Array; // Random padding for uniform message size

  // Group message fields
  isGroupMessage?: boolean;
  groupName?: string;
  senderId?: string;

  // Channel fields
  channelId?: string;

  encrypted?: Uint8Array;
  priority: MessagePriority;
  securityLevel: SecurityLevel;
  protectionLevel?: SecurityLevel;
  protectionTimestamp?: number;
  timingMarkers?: {
    processingStart: number;
    jitterApplied: number;
    processingEnd: number;
  };
  patternMarkers?: {
    patternType: string;
    splitCount: number;
    syntheticTraffic: boolean;
  };
  splitParts?: Array<{
    id: string;
    index: number;
    total: number;
    data: Uint8Array;
    metadata: Partial<MessageMetadata>;
  }>;
  synthetic?: boolean;
  tlsFingerprint?: {
    version: string;
    ciphers: string[];
    extensions: string[];
    ellipticCurves: string[];
    ecPointFormats: string[];
    signatureAlgorithms: string[];
    compressionMethods: string[];
    maxFragmentLength: number;
    recordSizeLimit: number;
  };
  requiresQuantumResistance?: boolean;
  useHeaderEncryption?: boolean;
  allowOutOfOrderMessages?: boolean;
  [key: string]: any;
}

/**
 * Security flags that can be attached to messages
 */
export interface SecurityFlags {
  ephemeral?: boolean; // Message should be auto-deleted after reading
  forwardingDisabled?: boolean; // Prevent message forwarding
  screenshotDisabled?: boolean; // Request screenshot prevention
  readReceiptEnabled?: boolean; // Request read receipt
  editDisabled?: boolean; // Disable message editing
}

/**
 * Transport information for message delivery
 */
export interface TransportInfo {
  protocol: string;
  routingPath?: string[];
  hops?: number;
  encryption?: string;
  latency?: number;
  fallbackUsed?: boolean;
}

/**
 * Message delivery status
 */
export enum MessageDeliveryStatus {
  PENDING = 'PENDING',
  SENT = 'SENT',
  DELIVERED = 'DELIVERED',
  READ = 'READ',
  FAILED = 'FAILED'
}

/**
 * Result of message sending operations
 */
export interface MessageSendResult {
  success: boolean;
  messageId?: string;
  timestamp?: number;
  protocol?: string;
  error?: string;
  deliveryStatus?: MessageDeliveryStatus;
}

/**
 * Options for sending messages
 */
export interface MessageSendOptions {
  priority?: MessagePriority;
  securityLevel?: SecurityLevel;
  metadata?: Partial<MessageMetadata>;
  ttl?: number; // Time to live in milliseconds
  ephemeral?: boolean;
  readReceipt?: boolean;
}

/**
 * A conversation between users
 */
export interface Conversation {
  id: string;
  participants: string[];
  created: number;
  lastActivity: number;
  name?: string;
  isGroup: boolean;
  metadata?: Record<string, any>;
}

/**
 * Message queue item for offline handling
 */
export interface QueuedMessage {
  message: Message;
  attempts: number;
  lastAttempt?: number;
  nextAttempt: number;
  expiresAt: number;
  priority: number;
}

/**
 * Message types for offline bundle exchange
 */
export enum OfflineSyncMessageType {
  OFFLINE_BUNDLE_REQUEST = 'OFFLINE_BUNDLE_REQUEST',
  OFFLINE_BUNDLE_RESPONSE = 'OFFLINE_BUNDLE_RESPONSE'
}

/**
 * Message types for PQC public key exchange
 */
export enum PqcKeyExchangeMessageType {
  PQC_PUBLIC_KEY_REQUEST = 'PQC_PUBLIC_KEY_REQUEST',
  PQC_PUBLIC_KEY_RESPONSE = 'PQC_PUBLIC_KEY_RESPONSE',
  PQC_KEM_ACK = 'PQC_KEM_ACK',
  PQC_KEM_ERROR = 'PQC_KEM_ERROR',
  PROTOCOL_ERROR = 'PROTOCOL_ERROR'
} 