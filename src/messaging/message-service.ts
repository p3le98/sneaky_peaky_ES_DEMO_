/**
 * @fileoverview Message Service
 * Service for handling secure messaging operations in the application
 */

import { 
  CryptoContext, 
  initCrypto, 
  createSecureSession, 
  isSessionQuantumResistant,
  upgradeSessionToQuantumResistant,
  completePqcSessionUpgrade,
  isQuantumResistanceAvailable
} from '../crypto/init';
import { SecureMessageHandler, MessageType, MessagePriority, MessageError, MessageMetadata, SecureMessage } from './secure-message-handler';
import { SessionMigrationManager, MigrationReason, MigrationParameters } from './session-migration-manager';
import { QuantumResistantProvider } from '../crypto/providers';
import { PqcKeyPair } from '../crypto/providers/crypto-provider';
import { KeyManager, KeyType } from '../crypto/key-manager';
import { OfflineMessageQueue, StoredMessage } from './offline/offline-message-queue';
import { ReputationSystem } from '../../js/anti-abuse/reputation-system';
import { VerifiableCredential } from '../identity/did-manager';
import { IssuedVcStore } from '../identity/issued-vc-store';
import { OfflineSyncMessageType, PqcKeyExchangeMessageType } from './message-types';
import { P2PTransport } from '../transport/p2p-transport';
import { TransportAdapter, TransportConfig } from './transport-adapter';
import { SecurityLevel } from '../core/security-levels';
import { Protocol } from '../core/protocol-types';
import { Message } from './message-types';
import { PersistenceManager, MessagePersistenceOptions } from '../crypto/persistence';

/**
 * Protocol capabilities interface for negotiation
 */
export interface ProtocolCapabilities {
  supportsQuantumResistance: boolean;
  supportsOutOfOrderMessages: boolean;
  supportsHeaderEncryption: boolean;
  maxMessageSize: number;
  protocolVersion: string;
  supportedExtensions?: string[]; // Additional protocol extensions
}

/**
 * Negotiated parameters result
 */
export interface NegotiatedParameters {
  requireQuantumResistance: boolean;
  useHeaderEncryption: boolean;
  allowOutOfOrderMessages: boolean;
  maxMessageSize: number;
  protocolVersion: string;
  agreedExtensions: string[];
}

/**
 * Negotiation state tracking
 */
export interface NegotiationState {
  chatId: string;
  peerId: string;
  initiated: number; // timestamp
  completed: number | null;
  localCapabilities: ProtocolCapabilities;
  peerCapabilities: ProtocolCapabilities | null;
  negotiatedParameters: NegotiatedParameters | null;
  attempts: number;
  status: 'pending' | 'completed' | 'failed';
  error?: string;
}

export type AutoNegotiateStatus = 
  | { status: 'established'; pqc?: boolean } 
  | { status: 'pending_peer_action'; pqc?: boolean; message?: string } 
  | { status: 'negotiating'; message?: string }
  | { status: 'failed'; error: string };

/**
 * Message Service
 * Provides an interface for secure messaging operations
 */
export class MessageService {
  private crypto: CryptoContext | null = null;
  private messageHandler: SecureMessageHandler | null = null;
  private sessionMigrationManager?: SessionMigrationManager;
  private offlineMessageQueue: OfflineMessageQueue;
  private userId: string;
  private reputationSystem: ReputationSystem;
  private issuedVcStore: IssuedVcStore;
  private initialized = false;
  private quantumResistanceSupported: boolean = false;
  private negotiationStates: Map<string, NegotiationState> = new Map();
  private readonly MAX_MESSAGE_SIZE = 100 * 1024 * 1024; // 100 MB
  private readonly MAX_NEGOTIATION_ATTEMPTS = 3;
  private readonly NEGOTIATION_RETRY_DELAY = 5000; // 5 seconds
  
  // Store own PQC key IDs
  private ownPqcPublicKeyId: string | null = null;
  private ownPqcPrivateKeyId: string | null = null;
  
  private transport?: P2PTransport;
  private transportAdapter?: TransportAdapter;
  private persistenceManager?: PersistenceManager;
  
  // Transport metrics tracking
  private transportMetrics = {
    successCount: new Map<Protocol, number>(),
    failureCount: new Map<Protocol, number>(),
    latencySum: new Map<Protocol, number>(),
    messageCount: new Map<Protocol, number>()
  };
  
  // Track pending PQC session establishment requests (by peerId)
  private pendingPqcSessionRequests: Map<string, { chatId: string, negotiatedParams: NegotiatedParameters, isUpgrade?: boolean }> = new Map();
  
  constructor(
    userId: string, 
    reputationSystem: ReputationSystem, 
    issuedVcStore: IssuedVcStore, 
    transport?: P2PTransport,
    transportAdapter?: TransportAdapter,
    persistenceManager?: PersistenceManager
  ) {
    this.userId = userId;
    this.reputationSystem = reputationSystem;
    this.issuedVcStore = issuedVcStore;
    this.offlineMessageQueue = new OfflineMessageQueue();
    this.transportAdapter = transportAdapter;
    this.persistenceManager = persistenceManager;
    
    if (transport) {
      this.transport = transport;
      // Wire up the offline bundle request handler
      this.transport.setOfflineBundleRequestHandler(async (requesterId: string) => {
        await this.handleOfflineBundleRequest(requesterId);
      });
    }
  }
  
  /**
   * Initialize the message service
   */
  async initialize(options: { 
    requireQuantumResistance?: boolean;
    useHardwareSecurity?: boolean;
  } = {}): Promise<void> {
    if (this.initialized) {
      return;
    }
    
    try {
      // Initialize crypto
      this.crypto = await initCrypto(options);
      
      // Create message handler
      this.messageHandler = new SecureMessageHandler(this.crypto, this.userId);
      
      // Create session migration manager
      this.sessionMigrationManager = new SessionMigrationManager(this.crypto);
      await this.sessionMigrationManager.initialize();
      
      // Set up migration state listener
      this.sessionMigrationManager.addMigrationStateListener(this.handleMigrationStateChange.bind(this));
      
      // Check and cache quantum resistance availability
      this.quantumResistanceSupported = await isQuantumResistanceAvailable(this.crypto.storage);
      
      if (this.quantumResistanceSupported) {
        // Attempt to generate and store PQC identity keys if they don't exist
        // This assumes a method to check for existence or that generateAndStore is idempotent / handles it.
        // For simplicity, we'll assume we can try to generate them.
        // A more robust approach would be to check if keys for `this.userId` already exist.
        try {
          // Check if we already have IDs (e.g., loaded from a persistent config not shown here)
          // For this example, we'll always try to generate if IDs are not set.
          if (!this.ownPqcPublicKeyId || !this.ownPqcPrivateKeyId) {
            console.log(`PQC supported. Generating/retrieving PQC identity keys for user ${this.userId}...`);
            const keyIds = await this.crypto.keyManager.generateAndStorePqcIdentityKeys(this.userId);
            this.ownPqcPublicKeyId = keyIds.pqcPublicKeyId;
            this.ownPqcPrivateKeyId = keyIds.pqcPrivateKeyId;
            console.log(`PQC identity keys processed. Public ID: ${this.ownPqcPublicKeyId}, Private ID: ${this.ownPqcPrivateKeyId}`);
            
            // TODO: The public PQC key (this.ownPqcPublicKeyId) should be published or made available
            // to peers (e.g., via a directory service, profile, or during initial contact exchange).
            // For now, we assume MessageService has access to peer PQC public keys when needed.
          }
        } catch (err) {
          console.error(`Failed to generate or store PQC identity keys for user ${this.userId}:`, err);
          // Depending on policy, we might want to set quantumResistanceSupported to false here
          // or let operations fail later if PQC keys are required but unavailable.
          this.quantumResistanceSupported = false; // Downgrade if PQC key setup fails
          console.warn('Quantum resistance disabled due to PQC key generation/storage failure.');
        }
      }
      
      this.initialized = true;
      console.log('Message service initialized with crypto context');
    } catch (error) {
      console.error('Failed to initialize message service:', error);
      throw new Error(`Initialization failed: ${(error as Error).message}`);
    }
  }
  
  /**
   * Get capabilities of this client for protocol negotiation
   */
  async getLocalCapabilities(): Promise<ProtocolCapabilities> {
    this.ensureInitialized();
    
    return {
      supportsQuantumResistance: this.quantumResistanceSupported,
      supportsOutOfOrderMessages: true, // DoubleRatchet always supports this
      supportsHeaderEncryption: true,   // DoubleRatchet always supports this
      maxMessageSize: this.MAX_MESSAGE_SIZE,
      protocolVersion: this.getProtocolVersion(),
      supportedExtensions: this.getSupportedExtensions()
    };
  }
  
  /**
   * Get supported protocol extensions
   */
  private getSupportedExtensions(): string[] {
    const extensions: string[] = ['message-receipts', 'typing-indicators'];
    
    // Add quantum resistance as an extension if supported
    if (this.quantumResistanceSupported) {
      extensions.push('quantum-resistance');
    }
    
    return extensions;
  }
  
  /**
   * Negotiate protocol capabilities with peer
   * Returns optimal security settings based on both peers' capabilities
   */
  negotiateCapabilities(
    peerCapabilities: ProtocolCapabilities
  ): NegotiatedParameters {
    this.ensureInitialized();
    
    // Find common capabilities between local and peer
    const localCapabilities = {
      supportsQuantumResistance: this.supportsQuantumResistance(),
      supportsOutOfOrderMessages: this.supportsOutOfOrderMessages(),
      supportsHeaderEncryption: this.supportsHeaderEncryption(),
      maxMessageSize: this.MAX_MESSAGE_SIZE,
      protocolVersion: this.getProtocolVersion(),
      supportedExtensions: this.getSupportedExtensions()
    };
    
    // Determine compatible protocol version
    const compatibleVersion = this.determineCompatibleVersion(
      this.getProtocolVersion(),
      peerCapabilities.protocolVersion
    );
    
    // Find common extensions
    const agreedExtensions = this.findCommonExtensions(
      localCapabilities.supportedExtensions || [],
      peerCapabilities.supportedExtensions || []
    );
    
    return {
      // Use most secure options available to both peers
      requireQuantumResistance: peerCapabilities.supportsQuantumResistance && 
                               localCapabilities.supportsQuantumResistance,
      useHeaderEncryption: peerCapabilities.supportsHeaderEncryption && 
                          localCapabilities.supportsHeaderEncryption,
      allowOutOfOrderMessages: peerCapabilities.supportsOutOfOrderMessages && 
                              localCapabilities.supportsOutOfOrderMessages,
      // Use the smaller of the two max message sizes
      maxMessageSize: Math.min(
        peerCapabilities.maxMessageSize, 
        localCapabilities.maxMessageSize
      ),
      protocolVersion: compatibleVersion,
      agreedExtensions
    };
  }
  
  /**
   * Find common extensions supported by both peers
   */
  private findCommonExtensions(localExtensions: string[], peerExtensions: string[]): string[] {
    return localExtensions.filter(ext => peerExtensions.includes(ext));
  }
  
  /**
   * Determine the highest compatible protocol version between local and peer
   */
  private determineCompatibleVersion(localVersion: string, peerVersion: string): string {
    const local = localVersion.split('.').map(Number);
    const peer = peerVersion.split('.').map(Number);
    
    // Major version must match for compatibility
    if (local[0] !== peer[0]) {
      // Different major versions are incompatible
      // Default to the lower major version for backward compatibility
      const majorVersion = Math.min(local[0], peer[0]);
      // If we're downgrading to an older major version, use the highest
      // minor and patch versions supported by that major version
      if (majorVersion === local[0]) {
        return localVersion;
      } else {
        return peerVersion;
      }
    }
    
    // If major versions match, use the minimum of minor versions
    const minorVersion = Math.min(local[1], peer[1]);
    
    // If both major and minor match, use minimum of patch versions
    // Otherwise use the highest patch of the lower minor version
    let patchVersion;
    if (local[1] === peer[1]) {
      patchVersion = Math.min(local[2], peer[2]);
    } else if (minorVersion === local[1]) {
      patchVersion = local[2];
    } else {
      patchVersion = peer[2];
    }
    
    return `${local[0]}.${minorVersion}.${patchVersion}`;
  }
  
  /**
   * Check if this client supports quantum-resistant cryptography
   */
  supportsQuantumResistance(): boolean {
    this.ensureInitialized();
    return this.quantumResistanceSupported;
  }
  
  /**
   * Upgrade a session to use quantum-resistant cryptography.
   * This is an older or internal-facing version.
   * It's called by other functions like autoNegotiateSecureSession.
   */
  async upgradeSessionSecurity(
    chatId: string,
    peerId: string
  ): Promise<{ success: boolean; requiresPeerAction: boolean }> {
    this.ensureInitialized();
    
    if (!this.crypto) {
      console.error("Crypto context not initialized in upgradeSessionSecurity.");
      return { success: false, requiresPeerAction: false };
    }

    try {
      if (!this.quantumResistanceSupported) {
        console.warn('Quantum-resistant cryptography not available on this device/client.');
        return { success: false, requiresPeerAction: false };
      }
      
      if (await isSessionQuantumResistant(this.crypto!, chatId, peerId)) {
        console.log(`Session ${chatId}-${peerId} is already quantum-resistant.`);
        return { success: true, requiresPeerAction: false };
      }
      
      const peerPqcPublicKeyBytes = await this.crypto.keyManager.getPeerPqcPublicKeyByPeerId(peerId);

      if (!peerPqcPublicKeyBytes) {
        console.warn(`Peer ${peerId} PQC public key not found. Requesting from peer...`);
        await this.requestPeerPqcPublicKey(peerId);
        // The session establishment should be retried once the key is received (see handlePqcPublicKeyResponse)
        return { success: false, requiresPeerAction: true };
      }
      
      const upgradeResult = await upgradeSessionToQuantumResistant(
        this.crypto!,
        chatId,
        peerId,
        peerPqcPublicKeyBytes
      );
      
      if (upgradeResult.success && upgradeResult.pqcCiphertext) {
        await this.sendPqcUpgradeKem(chatId, peerId, upgradeResult.pqcCiphertext);
        console.log(`PQC_UPGRADE_KEM sent to ${peerId} for session ${chatId}.`);
        return { success: true, requiresPeerAction: true };
      } else if (upgradeResult.success) {
         console.log(`PQC upgrade for ${chatId}-${peerId} completed by crypto layer, or was already PQC. No KEM data to send.`);
         return { success: true, requiresPeerAction: false };
      } else {
        console.error(`Crypto layer failed to upgrade session ${chatId}-${peerId} to PQC.`);
        return { success: false, requiresPeerAction: false };
      }
    } catch (error) {
      console.error(`Failed to upgrade session security for ${chatId}-${peerId}:`, error);
      return { success: false, requiresPeerAction: false };
    }
  }
  
  /**
   * Start a new secure session with a peer
   *
   * Enforces that protocol negotiation is complete and PQC is agreed before PQC session establishment.
   * If PQC is required but negotiation is not complete, aborts and sends a PROTOCOL_ERROR.
   *
   * @param chatId - The chat/session identifier
   * @param peerId - The peer's user identifier
   * @param isInitiator - True if this side is the initiator
   * @param negotiatedParams - Parameters agreed during protocol negotiation
   * @param preSharedSecret - Optional pre-shared secret for non-PQC sessions
   * @returns An object indicating success, and optionally the PQC ciphertext to send
   */
  async startSecureSession(
    chatId: string,
    peerId: string,
    isInitiator: boolean = true,
    negotiatedParams: NegotiatedParameters,
    preSharedSecret?: Uint8Array 
  ): Promise<{ success: boolean; pqcCiphertextToSend?: Uint8Array; finalSharedSecret?: Uint8Array }> {
    this.ensureInitialized();
    // Enforce negotiation state before PQC session establishment
    const negotiationKey = `${chatId}:${peerId}`;
    const negotiationState = this.negotiationStates.get(negotiationKey);
    if (negotiatedParams.requireQuantumResistance) {
      if (!negotiationState || negotiationState.status !== 'completed' || !negotiationState.negotiatedParameters?.requireQuantumResistance) {
        console.error(`[PROTOCOL] Attempted PQC session establishment before negotiation complete or PQC not agreed.`);
        await this.sendProtocolError(peerId, chatId, 'PQC session attempted before negotiation complete or PQC not agreed.');
        return { success: false };
      }
    }
    if (!this.crypto) {
      console.error("Crypto context not initialized in startSecureSession.");
      return { success: false };
    }
    let creationOptions: any = {
        isInitiator,
      requireQuantumResistance: negotiatedParams.requireQuantumResistance,
      useHeaderEncryption: negotiatedParams.useHeaderEncryption,
      allowOutOfOrderMessages: negotiatedParams.allowOutOfOrderMessages,
      protocolVersion: negotiatedParams.protocolVersion,
      maxMessageSize: negotiatedParams.maxMessageSize,
      agreedExtensions: negotiatedParams.agreedExtensions,
      sharedSecret: preSharedSecret
    };
    let sessionResult;
    if (negotiatedParams.requireQuantumResistance) {
      if (isInitiator) {
        if (!this.ownPqcPrivateKeyId) { 
          console.error('Own PQC private key ID not available. Cannot initiate PQC session.');
          return { success: false };
        }
        const peerPqcPublicKeyBytes = await this.crypto.keyManager.getPeerPqcPublicKeyByPeerId(peerId);
        if (!peerPqcPublicKeyBytes) {
          console.warn(`Peer ${peerId} PQC public key not found. Requesting from peer...`);
          await this.requestPeerPqcPublicKey(peerId);
          // Store pending request for retry
          this.pendingPqcSessionRequests.set(peerId, { chatId, negotiatedParams });
          return { success: false, pqcCiphertextToSend: undefined };
        }
        creationOptions.peerPqcPublicKeyBytes = peerPqcPublicKeyBytes;
        creationOptions.sharedSecret = undefined; 
        console.log(`Initiating PQC secure session with ${peerId}...`);
        sessionResult = await createSecureSession(this.crypto, chatId, peerId, creationOptions);
        if (sessionResult.success && sessionResult.pqcCiphertext) {
          await this.sendPqcSessionInitKem(chatId, peerId, sessionResult.pqcCiphertext);
          console.log(`PQC_SESSION_INIT_KEM sent to ${peerId} for new session ${chatId}.`);
        } else if (sessionResult.success) {
          console.log(`PQC session with ${peerId} established (crypto layer), but no KEM ciphertext returned (unexpected for initiator).`);
        } else {
          console.error(`Failed to initiate PQC session with ${peerId} at crypto layer.`);
        }
        return { 
          success: sessionResult.success,
          pqcCiphertextToSend: sessionResult.pqcCiphertext,
          finalSharedSecret: sessionResult.finalSharedSecret
        };
      } else {
        console.warn("PQC Responder path in startSecureSession should ideally be handled by a dedicated message handler.");
        return { success: false };
      }
    } else {
      console.log(`Initiating non-PQC secure session with ${peerId}...`);
      sessionResult = await createSecureSession(this.crypto, chatId, peerId, creationOptions);
      if (sessionResult.success) {
        console.log(`Non-PQC session with ${peerId} established (crypto layer).`);
      } else {
        console.error(`Failed to establish non-PQC session with ${peerId} at crypto layer.`);
      }
      return { 
        success: sessionResult.success,
        finalSharedSecret: sessionResult.finalSharedSecret
      };
    }
  }
  
  /**
   * Send a text message securely
   */
  async sendMessage(
    chatId: string,
    recipientId: string,
    text: string,
    priority: MessagePriority = MessagePriority.NORMAL,
    options: { selfDestruct?: boolean, destructionTimeMs?: number } = {}
  ): Promise<string> {
    this.ensureInitialized();
    
    try {
      const secureMessage = await this.messageHandler!.prepareTextMessage(
        chatId,
        recipientId,
        text,
        priority
      );
      
      // Store message in persistence layer first, if available
      if (this.persistenceManager) {
        const persistenceOptions: MessagePersistenceOptions = {
          selfDestruct: options.selfDestruct,
          destructionTimeMs: options.destructionTimeMs,
          retentionPeriodMs: 30 * 24 * 60 * 60 * 1000 // Default 30 days unless self-destructing
        };
        
        await this.persistenceManager.storeMessage(
          secureMessage.id,
          {
            content: secureMessage.encryptedContent,
            metadata: secureMessage.metadata,
            chatId,
            recipientId
          },
          persistenceOptions
        );
      }
      
      if (await this.isPeerOnline(recipientId)) {
        await this.dispatchSecureMessage(recipientId, secureMessage);
        console.log(`Message ${secureMessage.id} sent to ${recipientId}`);
      } else {
        const storedMessage: StoredMessage = {
          messageId: secureMessage.id,
          ciphertext: secureMessage.encryptedContent,
          recipientId: recipientId,
          senderId: this.userId,
          timestamp: secureMessage.metadata.timestamp,
          expiration: OfflineMessageQueue.calculateExpiration(),
          deliveryAttempts: 0,
          originalMetadata: secureMessage.metadata
        };
        await this.offlineMessageQueue.store(storedMessage);
        
        // Mark as offline in persistence layer
        if (this.persistenceManager) {
          await this.persistenceManager.storeMessage(
            secureMessage.id,
            {
              content: secureMessage.encryptedContent,
              metadata: secureMessage.metadata,
              chatId,
              recipientId
            },
            {
              ...options,
              isOffline: true,
              retentionPeriodMs: 30 * 24 * 60 * 60 * 1000 // Default 30 days
            }
          );
        }
        
        console.log(`Recipient ${recipientId} is offline. Message ${secureMessage.id} queued.`);
      }
      return secureMessage.id;
    } catch (error) {
      if (error instanceof MessageError) {
        if (error.code === 'NO_SESSION' && error.recoverable) {
          console.warn('No secure session exists. Need to establish a session first before queueing or sending.');
        }
        throw error;
      } else {
        console.error('Failed to send or queue message:', error);
        const errorMessage = error instanceof Error ? error.message : String(error);
        throw new Error(`Message sending/queueing failed: ${errorMessage}`);
      }
    }
  }
  
  /**
   * Send a file securely
   */
  async sendFile(
    chatId: string,
    recipientId: string,
    fileData: Uint8Array,
    fileName: string,
    contentType: string,
    priority: MessagePriority = MessagePriority.NORMAL
  ): Promise<string> {
    this.ensureInitialized();
    
    try {
      const secureMessage = await this.messageHandler!.prepareBinaryMessage(
        chatId,
        recipientId,
        fileData,
        MessageType.FILE,
        {
          contentType,
          fileName,
          fileSize: fileData.length,
          priority
        }
      );
      
      if (await this.isPeerOnline(recipientId)) {
        await this.dispatchSecureMessage(recipientId, secureMessage);
        console.log(`File ${secureMessage.id} sent to ${recipientId}`);
      } else {
        const storedMessage: StoredMessage = {
          messageId: secureMessage.id,
          ciphertext: secureMessage.encryptedContent,
          recipientId: recipientId,
          senderId: this.userId,
          timestamp: secureMessage.metadata.timestamp,
          expiration: OfflineMessageQueue.calculateExpiration(),
          deliveryAttempts: 0,
          originalMetadata: secureMessage.metadata
        };
        await this.offlineMessageQueue.store(storedMessage);
        console.log(`Recipient ${recipientId} is offline. File ${secureMessage.id} queued.`);
      }
      return secureMessage.id;
    } catch (error) {
      if (error instanceof MessageError) {
        throw error;
      } else {
        console.error('Failed to send or queue file:', error);
        const errorMessage = error instanceof Error ? error.message : String(error);
        throw new Error(`File sending/queueing failed: ${errorMessage}`);
      }
    }
  }
  
  /**
   * Receive and decrypt a message
   */
  async receiveMessage(
    chatId: string,
    senderId: string,
    encryptedData: Uint8Array,
    metadata: any
  ): Promise<any> {
    this.ensureInitialized();
    
    try {
      // Determine message type from metadata
      switch (metadata.type) {
        case MessageType.TEXT:
          const textResult = await this.messageHandler!.receiveTextMessage(
            chatId,
            senderId,
            encryptedData,
            metadata
          );
          console.log(`Received text message from ${senderId}: ${textResult.text.substring(0, 20)}...`);
          return textResult;
          
        case MessageType.IMAGE:
        case MessageType.FILE:
        case MessageType.AUDIO:
        case MessageType.VIDEO:
          const binaryResult = await this.messageHandler!.receiveMessage(
            chatId,
            senderId,
            encryptedData,
            metadata
          );
          console.log(`Received binary message of type ${metadata.type} from ${senderId}`);
          return binaryResult;
          
        case MessageType.PROTOCOL_NEGOTIATION:
          const protocolNegotiationResult = await this.messageHandler!.handleProtocolNegotiation(
            chatId,
            senderId,
            encryptedData,
            metadata
          );
          console.log(`Received protocol negotiation message from ${senderId}`);
          return protocolNegotiationResult;
          
        default:
          const result = await this.messageHandler!.receiveMessage(
            chatId,
            senderId,
            encryptedData,
            metadata
          );
          console.log(`Received message of type ${metadata.type} from ${senderId}`);
          return result;
      }
    } catch (error) {
      if (error instanceof MessageError) {
        // Handle specific message errors
        if (error.code === 'NO_SESSION') {
          console.warn('No secure session exists with this sender.');
        } else if (error.code === 'DECRYPTION_FAILED') {
          console.error('Message decryption failed. Possible protocol mismatch.');
        }
        throw error;
      } else {
        console.error('Failed to receive message:', error);
        throw new Error(`Message reception failed: ${error.message}`);
      }
    }
  }
  
  /**
   * Check if session with peer is using quantum-resistant cryptography
   */
  async isSessionQuantumResistant(chatId: string, peerId: string): Promise<boolean> {
    this.ensureInitialized();
    return await isSessionQuantumResistant(this.crypto!, chatId, peerId);
  }
  
  /**
   * Negotiate protocol capabilities with a peer to establish optimal secure channel
   */
  async negotiateProtocolWithPeer(
    chatId: string,
    peerId: string
  ): Promise<boolean> {
    this.ensureInitialized();
    
    try {
      // Get our local capabilities
      const localCapabilities = await this.getLocalCapabilities();
      
      // Create or update negotiation state
      const negotiationKey = `${chatId}:${peerId}`;
      let state = this.negotiationStates.get(negotiationKey);
      
      if (state && state.status === 'pending') {
        // Negotiation already in progress
        console.log(`Protocol negotiation already in progress with ${peerId}`);
        return true;
      }
      
      // Create new negotiation state
      state = {
        chatId,
        peerId,
        initiated: Date.now(),
        completed: null,
        localCapabilities,
        peerCapabilities: null,
        negotiatedParameters: null,
        attempts: 1,
        status: 'pending'
      };
      
      this.negotiationStates.set(negotiationKey, state);
      
      // Prepare protocol negotiation message
      const secureMessage = await this.messageHandler!.prepareProtocolNegotiation(
        chatId,
        peerId,
        localCapabilities,
        MessagePriority.HIGH
      );
      
      // Dispatch the message
      await this.dispatchSecureMessage(peerId, secureMessage);
      console.log(`Protocol negotiation initiated with ${peerId}, message ID: ${secureMessage.id}`);
      
      // Set timeout for retry if no response
      setTimeout(() => {
        this.checkNegotiationStatus(chatId, peerId);
      }, this.NEGOTIATION_RETRY_DELAY);
      
      return true;
    } catch (error) {
      console.error('Failed to negotiate protocol with peer:', error);
      
      // Update negotiation state to failed
      const negotiationKey = `${chatId}:${peerId}`;
      const state = this.negotiationStates.get(negotiationKey);
      
      if (state) {
        state.status = 'failed';
        state.error = error.message;
        this.negotiationStates.set(negotiationKey, state);
      }
      
      return false;
    }
  }
  
  /**
   * Check negotiation status and retry if needed
   */
  private async checkNegotiationStatus(chatId: string, peerId: string): Promise<void> {
    const negotiationKey = `${chatId}:${peerId}`;
    const state = this.negotiationStates.get(negotiationKey);
    
    if (!state || state.status !== 'pending') {
      return; // No pending negotiation or it's already completed/failed
    }
    
    // If we don't have a response and haven't exceeded max attempts, retry
    if (!state.peerCapabilities && state.attempts < this.MAX_NEGOTIATION_ATTEMPTS) {
      state.attempts++;
      this.negotiationStates.set(negotiationKey, state);
      
      console.log(`Retrying protocol negotiation with ${peerId} (attempt ${state.attempts})`);
      
      try {
        // Prepare protocol negotiation message again
        const secureMessage = await this.messageHandler!.prepareProtocolNegotiation(
          chatId,
          peerId,
          state.localCapabilities,
          MessagePriority.HIGH
        );
        // Dispatch the message
        await this.dispatchSecureMessage(peerId, secureMessage);
        
        // Set timeout for next retry
        setTimeout(() => {
          this.checkNegotiationStatus(chatId, peerId);
        }, this.NEGOTIATION_RETRY_DELAY);
      } catch (error) {
        console.error('Failed to retry protocol negotiation:', error);
        
        // Mark as failed if we can't retry
        state.status = 'failed';
        state.error = error.message;
        this.negotiationStates.set(negotiationKey, state);
      }
    } else if (!state.peerCapabilities) {
      // Exceeded max attempts, mark as failed
      state.status = 'failed';
      state.error = 'Max negotiation attempts exceeded';
      this.negotiationStates.set(negotiationKey, state);
      
      console.warn(`Protocol negotiation with ${peerId} failed after ${state.attempts} attempts`);
    }
  }
  
  /**
   * Handle protocol negotiation response from peer
   */
  async handleProtocolNegotiationResponse(
    chatId: string,
    peerId: string,
    encryptedMessage: Uint8Array,
    metadata: MessageMetadata
  ): Promise<boolean> {
    this.ensureInitialized();
    
    try {
      // Process the protocol negotiation message using the existing handler in SecureMessageHandler
      // Note: handleProtocolNegotiation in SecureMessageHandler was not renamed.
      const peerCapabilities = await this.messageHandler!.handleProtocolNegotiation(
        chatId,
        peerId,
        encryptedMessage,
        metadata
      );
      
      // Update negotiation state
      const negotiationKey = `${chatId}:${peerId}`;
      let state = this.negotiationStates.get(negotiationKey);
      
      if (!state) {
        // This is a response to a negotiation we didn't initiate
        // Create a new negotiation state
        state = {
          chatId,
          peerId,
          initiated: Date.now(),
          completed: null,
          localCapabilities: await this.getLocalCapabilities(),
          peerCapabilities: null,
          negotiatedParameters: null,
          attempts: 1,
          status: 'pending'
        };
      }
      
      // Update with peer capabilities
      state.peerCapabilities = peerCapabilities;
      
      // Determine optimal security parameters
      const negotiatedParameters = this.negotiateCapabilities(peerCapabilities);
      state.negotiatedParameters = negotiatedParameters;
      
      // Mark negotiation as complete
      state.completed = Date.now();
      state.status = 'completed';
      this.negotiationStates.set(negotiationKey, state);
      
      console.log(`Protocol negotiation with ${peerId} completed successfully`);
      
      // If peer supports quantum resistance and we're not already using it, upgrade
      if (negotiatedParameters.requireQuantumResistance && 
          !await this.isSessionQuantumResistant(chatId, peerId)) {
        
        // Upgrade the session to quantum resistance
        const upgraded = await this.upgradeSessionSecurity(chatId, peerId);
        
        if (upgraded.success) {
          console.log(`Session with ${peerId} upgraded to quantum-resistant cryptography`);
        } else {
          console.warn(`Failed to upgrade session with ${peerId} to quantum-resistant cryptography`);
        }
        
        return upgraded.success;
      }
      
      return true;
    } catch (error) {
      console.error('Failed to handle protocol negotiation response:', error);
      
      // Update negotiation state to failed
      const negotiationKey = `${chatId}:${peerId}`;
      const state = this.negotiationStates.get(negotiationKey);
      
      if (state) {
        state.status = 'failed';
        state.error = error.message;
        this.negotiationStates.set(negotiationKey, state);
      }
      
      return false;
    }
  }
  
  /**
   * Get the current negotiation state for a peer
   */
  getNegotiationState(chatId: string, peerId: string): NegotiationState | null {
    const negotiationKey = `${chatId}:${peerId}`;
    return this.negotiationStates.get(negotiationKey) || null;
  }
  
  /**
   * Ensure the service is initialized
   */
  private ensureInitialized(): void {
    if (!this.initialized || !this.crypto || !this.messageHandler || !this.sessionMigrationManager) {
      throw new Error('Message service is not initialized. Call initialize() first.');
    }
  }
  
  /**
   * Check if out-of-order messages are supported
   */
  supportsOutOfOrderMessages(): boolean {
    this.ensureInitialized();
    return this.messageHandler!.supportsOutOfOrderMessages();
  }
  
  /**
   * Check if header encryption is supported
   */
  supportsHeaderEncryption(): boolean {
    this.ensureInitialized();
    return this.messageHandler!.supportsHeaderEncryption();
  }
  
  /**
   * Get the current protocol version as a string
   */
  getProtocolVersion(): string {
    this.ensureInitialized();
    return this.crypto!.protocolVersion.major + '.' + 
           this.crypto!.protocolVersion.minor + '.' + 
           this.crypto!.protocolVersion.patch;
  }
  
  /**
   * Set the session migration manager
   * @param migrationManager The session migration manager
   */
  async setSessionMigrationManager(migrationManager: SessionMigrationManager): Promise<void> {
    this.sessionMigrationManager = migrationManager;
    await this.sessionMigrationManager.initialize();
  }
  
  /**
   * Auto-negotiate and create a secure session with a peer
   * This is a convenience method that combines negotiation and session creation
   */
  async autoNegotiateSecureSession(
    chatId: string,
    peerId: string,
    isInitiator: boolean = true,
    // preSharedSecret is used ONLY if non-PQC session is negotiated
    // and a pre-shared key mechanism (not DHR) is desired.
    preSharedSecret?: Uint8Array 
  ): Promise<AutoNegotiateStatus> {
    this.ensureInitialized();
    if (!this.crypto) { // Redundant with ensureInitialized but good for type narrowing
        return { status: 'failed', error: 'Crypto context not initialized.' };
    }
    console.log(`Auto-negotiating session for ${chatId}-${peerId}, initiator: ${isInitiator}`);
        
    // 1. Handle Capability Negotiation
    let negotiationState = this.getNegotiationState(chatId, peerId);

    if (!negotiationState || negotiationState.status === 'failed' || 
        (negotiationState.status === 'completed' && !negotiationState.negotiatedParameters)) {
      // No valid completed negotiation, or negotiation failed previously. Initiate a new one.
      console.log(`No valid negotiation state for ${peerId}, initiating new negotiation.`);
      try {
        const initiated = await this.negotiateProtocolWithPeer(chatId, peerId);
        if (initiated) {
          return { status: 'negotiating', message: 'Protocol negotiation initiated.' };
        } else {
          return { status: 'failed', error: 'Failed to initiate protocol negotiation.' };
        }
      } catch (error: any) {
        return { status: 'failed', error: `Negotiation initiation error: ${error.message}` };
      }
    }

    if (negotiationState.status === 'pending') {
      return { status: 'negotiating', message: 'Protocol negotiation is pending.' };
    }

    // At this point, negotiationState.status === 'completed' and negotiatedParameters should exist
    const negotiatedParams = negotiationState.negotiatedParameters;
    if (!negotiatedParams) {
        // Should not happen if status is 'completed', but as a safeguard:
        return { status: 'failed', error: 'Negotiation completed but parameters are missing.' };
    }

    console.log(`Negotiated parameters for ${peerId}:`, negotiatedParams);

    // 2. Proceed with session establishment/upgrade based on negotiated parameters
    if (negotiatedParams.requireQuantumResistance) {
      console.log(`PQC required for session with ${peerId}.`);
      const isCurrentlyPqc = await this.isSessionQuantumResistant(chatId, peerId);
        
      if (isCurrentlyPqc) {
        console.log(`Session ${chatId}-${peerId} is already PQC.`);
        return { status: 'established', pqc: true };
      }

      // Session is not yet PQC, needs upgrade or new PQC establishment.
      if (isInitiator) {
        console.log(`Initiator for ${peerId}: Session is not PQC. Attempting to establish/upgrade to PQC.`);
        const startResult = await this.startSecureSession(chatId, peerId, true, negotiatedParams);
        if (startResult.success && startResult.pqcCiphertextToSend) {
          return { status: 'pending_peer_action', pqc: true, message: 'PQC session initiation KEM sent. Waiting for peer.' };
        } else if (startResult.success) { // PQC session established without KEM (should not happen for initiator if new)
          // This case might occur if startSecureSession internally found it was already PQC after a race condition, or if PQC setup didn't need KEM send (unlikely for our KEM model)
          return { status: 'established', pqc: true };
        } else {
          return { status: 'failed', error: 'Failed to start/upgrade PQC session as initiator.' };
        }
      } else { // Responder
        console.log(`Responder for ${peerId}: PQC required, session not yet PQC. Awaiting KEM from initiator.`);
        // Responder logic is passive here; action happens in handlePqcSessionInitKem or handlePqcUpgradeKem
        return { status: 'pending_peer_action', pqc: true, message: 'Awaiting PQC KEM data from peer.' };
      }
    } else { // Non-PQC session
      console.log(`Non-PQC session required for ${peerId}.`);
      // Use preSharedSecret if provided for non-PQC, otherwise DHR will occur in startSecureSession
      const startResult = await this.startSecureSession(chatId, peerId, isInitiator, negotiatedParams, preSharedSecret);
      if (startResult.success) {
        return { status: 'established', pqc: false };
      } else {
        return { status: 'failed', error: 'Failed to establish non-PQC session.' };
      }
    }
  }
  
  /**
   * Handle a received message
   */
  async handleReceivedMessage(
    chatId: string,
    senderId: string,
    encryptedMessage: Uint8Array,
    receivedMetadata: any
  ): Promise<any> {
    this.ensureInitialized();
    
    try {
      // Decrypt and process the message to get the actual content and verified metadata
      // The `this.messageHandler.receiveMessage` is responsible for decryption using the existing session (if any)
      // and returning the plaintext content along with the sender-provided metadata.
      const { content, metadata, type } = await this.messageHandler!.receiveMessage(
        chatId,
        senderId,
        encryptedMessage,
        receivedMetadata // Pass raw received metadata here
      );
      
      // Handle different message types based on the *verified* metadata.type from SecureMessageHandler
      switch (type) {
        case MessageType.SESSION_MIGRATION_INIT:
          return this.handleSessionMigrationInit(chatId, senderId, content, metadata);
        case MessageType.SESSION_MIGRATION_ACCEPT:
          return this.handleSessionMigrationAccept(chatId, senderId, content, metadata);
        case MessageType.SESSION_MIGRATION_COMPLETE:
          return this.handleSessionMigrationComplete(chatId, senderId, content, metadata);
        case MessageType.SESSION_MIGRATION_REJECT:
          return this.handleSessionMigrationReject(chatId, senderId, content, metadata);
        case MessageType.PROTOCOL_NEGOTIATION:
          return this.handleProtocolNegotiationMessage(chatId, senderId, content, metadata);
        case MessageType.PQC_SESSION_INIT_KEM: // New PQC Session KEM data from Initiator
          console.log(`Received PQC_SESSION_INIT_KEM from ${senderId} for chat ${chatId}.`);
          return this.handlePqcSessionInitKem(chatId, senderId, content, metadata);
        case MessageType.PQC_UPGRADE_KEM: // PQC Upgrade KEM data from Initiator
          console.log(`Received PQC_UPGRADE_KEM from ${senderId} for chat ${chatId}.`);
          return this.handlePqcUpgradeKem(chatId, senderId, content, metadata);
        case MessageType.VERIFIABLE_CREDENTIAL:
          try {
            const vcString = new TextDecoder().decode(content);
            const vc = JSON.parse(vcString) as VerifiableCredential;
            
            // Ensure reputation system is initialized (important if it has its own async init)
            // If ReputationSystem.initialize is idempotent, this is safe.
            // Alternatively, ensure MessageService only gets a fully initialized ReputationSystem.
            if (this.reputationSystem && typeof (this.reputationSystem as any).initialize === 'function' && !(this.reputationSystem as any).initialized) {
              // This check is a bit defensive; ideally, ReputationSystem is initialized when MessageService is.
              await (this.reputationSystem as any).initialize(); 
            }

            await this.reputationSystem.recordTrust(vc);
            console.log(`Processed Verifiable Credential ID: ${vc.id || 'N/A'}, Type: ${vc.type.join(', ')}, Issuer: ${vc.issuer}`);
            return {
              type: 'verifiable_credential_processed',
              vcId: vc.id,
              issuer: vc.issuer,
              metadata: metadata
            };
          } catch (error) {
            const errMessage = error instanceof Error ? error.message : String(error);
            console.error(`Error processing received Verifiable Credential from ${senderId}: ${errMessage}. VC Raw Content: ${new TextDecoder().decode(content)}`);
            return {
              type: 'verifiable_credential_failed',
              error: errMessage,
              metadata: metadata
            };
          }
        default:
          // For standard messages like TEXT, FILE, etc., the content is the decrypted user data.
          // Application layer would handle this content.
          console.log(`Received standard message of type ${type} from ${senderId}.`);
          return { content, metadata, type }; // Return it for further app processing
      }
    } catch (error) {
      console.error(`Error handling received message from ${senderId} in chat ${chatId}:`, error);
      // Depending on the error, might need to notify user or take other actions.
      // For privacy, avoid logging sensitive details from the error if it might contain parts of the message.
      throw error; // Re-throw for higher-level error handling if any
    }
  }
  
  /**
   * Initiate session migration
   */
  async initiateSessionMigration(
    chatId: string,
    peerId: string,
    targetParameters: MigrationParameters,
    reason: MigrationReason
  ): Promise<string> {
    this.ensureInitialized();
    
    try {
      const migrationState = await this.sessionMigrationManager!.initiateMigration(
        chatId,
        peerId,
        targetParameters,
        reason,
        true // Require acknowledgment
      );
      
      return migrationState.id;
    } catch (error) {
      console.error('Failed to initiate session migration:', error);
      throw new Error(`Failed to initiate session migration: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
  
  /**
   * Handle session migration init message
   */
  private async handleSessionMigrationInit(
    chatId: string,
    senderId: string,
    content: Uint8Array,
    metadata: any
  ): Promise<void> {
    try {
      // Convert content to JSON
      const contentString = new TextDecoder().decode(content);
      const migrationData = JSON.parse(contentString);
      
      // Handle the migration init message
      await this.sessionMigrationManager!.handleMigrationInitMessage(
        chatId,
        senderId,
        migrationData
      );
      
      return;
    } catch (error) {
      console.error('Failed to handle session migration init:', error);
      throw error;
    }
  }
  
  /**
   * Handle session migration accept message
   */
  private async handleSessionMigrationAccept(
    chatId: string,
    senderId: string,
    content: Uint8Array,
    metadata: any
  ): Promise<void> {
    try {
      // Convert content to JSON
      const contentString = new TextDecoder().decode(content);
      const acceptData = JSON.parse(contentString);
      
      // Get migration ID from metadata or content
      const migrationId = acceptData.migrationId || (metadata.customData && metadata.customData.migrationId);
      
      if (!migrationId) {
        throw new Error('Missing migration ID in accept message');
      }
      
      console.log(`Received migration accept message for migration ${migrationId}`);
      
      // Find migration state
      const migrationState = this.sessionMigrationManager!.getMigrationStateById(migrationId);
      if (!migrationState) {
        console.warn(`No migration state found for ID ${migrationId}`);
        return;
      }
      
      // Update migration state
      // The migration will continue its process based on the state
      
      return;
    } catch (error) {
      console.error('Failed to handle session migration accept:', error);
      throw error;
    }
  }
  
  /**
   * Handle session migration complete message
   */
  private async handleSessionMigrationComplete(
    chatId: string,
    senderId: string,
    content: Uint8Array,
    metadata: any
  ): Promise<void> {
    try {
      // Convert content to JSON
      const contentString = new TextDecoder().decode(content);
      const completeData = JSON.parse(contentString);
      
      // Get migration ID from metadata or content
      const migrationId = completeData.migrationId || (metadata.customData && metadata.customData.migrationId);
      
      if (!migrationId) {
        throw new Error('Missing migration ID in complete message');
      }
      
      console.log(`Received migration complete message for migration ${migrationId}`);
      
      // Find migration state
      const migrationState = this.sessionMigrationManager!.getMigrationStateById(migrationId);
      if (!migrationState) {
        console.warn(`No migration state found for ID ${migrationId}`);
        return;
      }
      
      // Migration completed successfully
      // We can now clean up any backup data if needed
      
      return;
    } catch (error) {
      console.error('Failed to handle session migration complete:', error);
      throw error;
    }
  }
  
  /**
   * Handle session migration reject message
   */
  private async handleSessionMigrationReject(
    chatId: string,
    senderId: string,
    content: Uint8Array,
    metadata: any
  ): Promise<void> {
    try {
      // Convert content to JSON
      const contentString = new TextDecoder().decode(content);
      const rejectData = JSON.parse(contentString);
      
      // Get migration ID from metadata or content
      const migrationId = rejectData.migrationId || (metadata.customData && metadata.customData.migrationId);
      
      if (!migrationId) {
        throw new Error('Missing migration ID in reject message');
      }
      
      console.log(`Received migration reject message for migration ${migrationId}: ${rejectData.reason}`);
      
      // Find migration state
      const migrationState = this.sessionMigrationManager!.getMigrationStateById(migrationId);
      if (!migrationState) {
        console.warn(`No migration state found for ID ${migrationId}`);
        return;
      }
      
      // Restore from backup if needed
      if (migrationState.backupCreated) {
        await this.sessionMigrationManager!.restoreFromBackup(
          chatId,
          senderId,
          migrationId
        );
      }
      
      return;
    } catch (error) {
      console.error('Failed to handle session migration reject:', error);
      throw error;
    }
  }
  
  /**
   * Handle migration state changes
   */
  private handleMigrationStateChange(state: any): void {
    // This method can be used to notify UI or other components about migration progress
    console.log(`Migration state changed: ${state.id}, status: ${state.status}`);
    
    // In a real application, we might dispatch events, update UI, etc.
  }
  
  /**
   * Handle protocol negotiation message
   */
  private async handleProtocolNegotiationMessage(
    chatId: string,
    senderId: string,
    content: Uint8Array,
    metadata: any
  ): Promise<any> {
    try {
      // Convert content to JSON
      const contentString = new TextDecoder().decode(content);
      const negotiationData = JSON.parse(contentString);
      
      console.log(`Received protocol negotiation message from ${senderId} in chat ${chatId}`);
      
      // Process the negotiation data
      // In a real implementation, this would update the local protocol preferences
      // based on what the peer supports
      
      // We'll return the processed negotiation response
      return {
        accepted: true,
        capabilities: this.getLocalCapabilities()
      };
    } catch (error) {
      console.error('Failed to handle protocol negotiation message:', error);
      throw error;
    }
  }

  // Helper to send PQC_SESSION_INIT_KEM
  private async sendPqcSessionInitKem(chatId: string, peerId: string, kemCiphertext: Uint8Array): Promise<string> {
    this.ensureInitialized();
    console.log(`Preparing PQC_SESSION_INIT_KEM for ${peerId} for chat ${chatId}.`);
    try {
      const secureMessage = await this.messageHandler!.prepareBinaryMessage(
        chatId,
        peerId,
        kemCiphertext,
        MessageType.PQC_SESSION_INIT_KEM,
        {
          priority: MessagePriority.HIGH,
          contentType: 'application/vnd.pqc-kem-ciphertext'
        }
      );

      // KEM messages are critical and part of an active handshake, assume online or let dispatch fail.
      // Offline queueing for these might complicate handshake state.
      await this.dispatchSecureMessage(peerId, secureMessage);
      console.log(`PQC_SESSION_INIT_KEM ${secureMessage.id} dispatched to ${peerId}.`);
      return secureMessage.id;
    } catch (error) {
      console.error(`Failed to prepare or dispatch PQC_SESSION_INIT_KEM to ${peerId}:`, error);
      throw error;
    }
  }

  // Helper to send PQC_UPGRADE_KEM
  private async sendPqcUpgradeKem(chatId: string, peerId: string, kemCiphertext: Uint8Array): Promise<string> {
    this.ensureInitialized();
    console.log(`Preparing PQC_UPGRADE_KEM for ${peerId} for chat ${chatId}.`);
    try {
      const secureMessage = await this.messageHandler!.prepareBinaryMessage(
        chatId,
        peerId,
        kemCiphertext,
        MessageType.PQC_UPGRADE_KEM,
        {
          priority: MessagePriority.HIGH,
          contentType: 'application/vnd.pqc-kem-ciphertext'
        }
      );
      // Similar to INIT_KEM, assume online for upgrade messages.
      await this.dispatchSecureMessage(peerId, secureMessage);
      console.log(`PQC_UPGRADE_KEM ${secureMessage.id} dispatched to ${peerId}.`);
      return secureMessage.id;
    } catch (error) {
      console.error(`Failed to prepare or dispatch PQC_UPGRADE_KEM to ${peerId}:`, error);
      throw error;
    }
  }

  /**
   * Send a PQC KEM ACK control message to a peer
   */
  private async sendPqcKemAck(peerId: string, chatId: string): Promise<void> {
    if (!this.transport || typeof this.transport.sendControlMessage !== 'function') return;
    const ackMessage = {
      type: PqcKeyExchangeMessageType.PQC_KEM_ACK,
      chatId,
      senderId: this.userId
    };
    await this.transport.sendControlMessage(peerId, ackMessage);
    console.log(`Sent PQC_KEM_ACK to ${peerId} for chat ${chatId}`);
  }

  /**
   * Send a PQC KEM ERROR control message to a peer
   */
  private async sendPqcKemError(peerId: string, chatId: string, error: string): Promise<void> {
    if (!this.transport || typeof this.transport.sendControlMessage !== 'function') return;
    const errorMessage = {
      type: PqcKeyExchangeMessageType.PQC_KEM_ERROR,
      chatId,
      senderId: this.userId,
      error
    };
    await this.transport.sendControlMessage(peerId, errorMessage);
    console.log(`Sent PQC_KEM_ERROR to ${peerId} for chat ${chatId}: ${error}`);
  }

  /**
   * Handler for PQC KEM ACK control message (initiator side)
   */
  private async handlePqcKemAck(senderId: string, chatId: string): Promise<void> {
    // Mark handshake as complete, update session state, notify UI, etc.
    console.log(`[PQC] Received KEM ACK from ${senderId} for chat ${chatId}. PQC handshake complete.`);
    // TODO: Mark session as established/ready in state, notify listeners/UI, etc.
  }

  /**
   * Handler for PQC KEM ERROR control message (initiator side)
   */
  private async handlePqcKemError(senderId: string, chatId: string, error: string): Promise<void> {
    // Mark handshake as failed, update session state, notify UI, etc.
    console.error(`[PQC] Received KEM ERROR from ${senderId} for chat ${chatId}: ${error}`);
    // TODO: Mark session as failed, notify listeners/UI, retry or abort as appropriate.
  }

  /**
   * Handle PQC_SESSION_INIT_KEM message (responder side)
   *
   * Enforces that protocol negotiation is complete and PQC is agreed before accepting KEM.
   * Handles out-of-order, duplicate, or delayed KEM/control messages robustly.
   * If a PQC session is already established, ACK and ignore. If duplicate, ignore or ACK.
   *
   * @param chatId - The chat/session identifier
   * @param senderId - The peer who sent the KEM
   * @param pqcCiphertextBytes - The KEM ciphertext from the initiator
   * @param messageMetadata - Metadata of the PQC_SESSION_INIT_KEM message
   */
  private async handlePqcSessionInitKem(
    chatId: string, 
    senderId: string, 
    pqcCiphertextBytes: Uint8Array, 
    messageMetadata: MessageMetadata 
  ): Promise<void> {
    this.ensureInitialized();
    // Enforce negotiation state before accepting PQC KEM
    const negotiationKey = `${chatId}:${senderId}`;
    const negotiationState = this.negotiationStates.get(negotiationKey);
    if (!negotiationState || negotiationState.status !== 'completed' || !negotiationState.negotiatedParameters?.requireQuantumResistance) {
      console.error(`[PROTOCOL] Received PQC KEM before negotiation complete or PQC not agreed.`);
      await this.sendProtocolError(senderId, chatId, 'Received PQC KEM before negotiation complete or PQC not agreed.');
      return;
    }
    // Check if PQC session is already established
    if (await this.isSessionQuantumResistant(chatId, senderId)) {
      console.warn(`[PQC] PQC session already established for ${chatId}-${senderId}. Ignoring duplicate or delayed KEM.`);
      await this.sendPqcKemAck(senderId, chatId); // Idempotent ACK
      return;
    }
    // TODO: Optionally, check for duplicate KEM ciphertext (replay protection)
    if (!this.crypto || !this.ownPqcPrivateKeyId) {
      console.error('Cannot handle PQC_SESSION_INIT_KEM: Service not ready or PQC private key ID missing.');
      await this.sendPqcKemError(senderId, chatId, 'Responder not ready or missing PQC private key.');
      return;
    }
    const ownPqcPrivateKeyBytes = await this.crypto.keyManager.getOwnPqcPrivateKeyById(this.ownPqcPrivateKeyId);
    if (!ownPqcPrivateKeyBytes) {
      console.error('Cannot handle PQC_SESSION_INIT_KEM: Own PQC private key data could not be retrieved.');
      await this.sendPqcKemError(senderId, chatId, 'Responder PQC private key not found.');
      return;
    }
    // Assume negotiated parameters are available or can be derived for this new session.
    // For simplicity, using default or broadly compatible parameters.
    // In a real system, these would come from prior capability exchange (ProtocolNegotiation message type).
    const negotiatedParams: NegotiatedParameters = {
      requireQuantumResistance: true, // Implicitly true as we are handling PQC KEM
      useHeaderEncryption: true,
      allowOutOfOrderMessages: true,
      maxMessageSize: this.MAX_MESSAGE_SIZE,
      protocolVersion: this.getProtocolVersion(), // Or version from initiator's message if available
      agreedExtensions: [] // Or from negotiation
    };

    const creationOptions = {
      isInitiator: false, // This node is the responder
      pqcCiphertextBytes,
      ownPqcPrivateKeyBytes,
      requireQuantumResistance: true,
      useHeaderEncryption: negotiatedParams.useHeaderEncryption,
      allowOutOfOrderMessages: negotiatedParams.allowOutOfOrderMessages,
      protocolVersion: negotiatedParams.protocolVersion,
      maxMessageSize: negotiatedParams.maxMessageSize,
      agreedExtensions: negotiatedParams.agreedExtensions
    };

    const sessionResult = await createSecureSession(this.crypto, chatId, senderId, creationOptions);

    if (sessionResult.success) {
      console.log(`Successfully established PQC session with ${senderId} in chat ${chatId} (as responder).`);
      await this.sendPqcKemAck(senderId, chatId);
    } else {
      console.error(`Failed to establish PQC session with ${senderId} in chat ${chatId} (as responder).`);
      await this.sendPqcKemError(senderId, chatId, 'Session establishment failed.');
    }
  }

  /**
   * Handle PQC_UPGRADE_KEM message (responder side)
   *
   * Enforces that protocol negotiation is complete and PQC is agreed before accepting KEM.
   * Handles out-of-order, duplicate, or delayed KEM/control messages robustly.
   * If a PQC session is already established, ACK and ignore. If duplicate, ignore or ACK.
   *
   * @param chatId - The chat/session identifier
   * @param senderId - The peer who sent the upgrade KEM
   * @param pqcCiphertextBytes - The KEM ciphertext from the initiator
   * @param messageMetadata - Metadata of the PQC_UPGRADE_KEM message
   */
  private async handlePqcUpgradeKem(
    chatId: string, 
    senderId: string, 
    pqcCiphertextBytes: Uint8Array, 
    messageMetadata: MessageMetadata 
  ): Promise<void> {
    this.ensureInitialized();
    // Enforce negotiation state before accepting PQC KEM
    const negotiationKey = `${chatId}:${senderId}`;
    const negotiationState = this.negotiationStates.get(negotiationKey);
    if (!negotiationState || negotiationState.status !== 'completed' || !negotiationState.negotiatedParameters?.requireQuantumResistance) {
      console.error(`[PROTOCOL] Received PQC upgrade KEM before negotiation complete or PQC not agreed.`);
      await this.sendProtocolError(senderId, chatId, 'Received PQC upgrade KEM before negotiation complete or PQC not agreed.');
      return;
    }
    // Check if PQC session is already established
    if (await this.isSessionQuantumResistant(chatId, senderId)) {
      console.warn(`[PQC] PQC session already established for ${chatId}-${senderId}. Ignoring duplicate or delayed upgrade KEM.`);
      await this.sendPqcKemAck(senderId, chatId); // Idempotent ACK
      return;
    }
    // TODO: Optionally, check for duplicate KEM ciphertext (replay protection)
    if (!this.crypto || !this.ownPqcPrivateKeyId) {
      console.error('Cannot handle PQC_UPGRADE_KEM: Service not ready or PQC private key ID missing.');
      await this.sendPqcKemError(senderId, chatId, 'Responder not ready or missing PQC private key.');
      return;
    }
    const ownPqcPrivateKeyBytes = await this.crypto.keyManager.getOwnPqcPrivateKeyById(this.ownPqcPrivateKeyId);
    if (!ownPqcPrivateKeyBytes) {
      console.error('Cannot handle PQC_UPGRADE_KEM: Own PQC private key data could not be retrieved.');
      await this.sendPqcKemError(senderId, chatId, 'Responder PQC private key not found.');
      return;
    }
    const upgradeCompletionResult = await completePqcSessionUpgrade(
      this.crypto,
      chatId,
      senderId,
      pqcCiphertextBytes,
      ownPqcPrivateKeyBytes
    );
    if (upgradeCompletionResult.success) {
      console.log(`Successfully completed PQC session upgrade with ${senderId} in chat ${chatId} (as responder).`);
      await this.sendPqcKemAck(senderId, chatId);
    } else {
      console.error(`Failed to complete PQC session upgrade with ${senderId} in chat ${chatId} (as responder).`);
      await this.sendPqcKemError(senderId, chatId, 'Session upgrade failed.');
    }
  }

  // Placeholder for actual peer presence/reachability logic
  private async isPeerOnline(peerId: string): Promise<boolean> {
    this.ensureInitialized();
    // In a real implementation, this would query a presence service,
    // check network status, or use libp2p peer routing etc.
    // console.warn(`isPeerOnline check for ${peerId} is a placeholder and currently assumes online.`);
    // For testing offline flow, uncomment next line and ensure MessageService.syncOfflineMessages is called:
    // if (peerId === "testOfflinePeer") return false;
    return true; // Default to true for now
  }

  private async dispatchSecureMessage(recipientId: string, secureMessage: SecureMessage): Promise<void> {
    this.ensureInitialized();
    
    try {
      if (this.transportAdapter) {
        // Use transport adapter for message routing
        const message: Message = {
          id: secureMessage.id,
          chatId: secureMessage.metadata.chatId,
          senderId: this.userId,
          recipient: recipientId,
          content: secureMessage.encryptedContent,
          timestamp: secureMessage.metadata.timestamp,
          priority: secureMessage.metadata.priority,
          securityLevel: secureMessage.metadata.securityLevel,
          size: secureMessage.encryptedContent.length,
          metadata: secureMessage.metadata
        };

        const result = await this.transportAdapter.sendMessage(message);
        
        if (!result.success) {
          throw new Error(result.error || 'Failed to send message via transport adapter');
        }
      } else if (this.transport) {
        // Fallback to direct P2P transport if no adapter
        await this.transport.sendMessage(recipientId, secureMessage.encryptedContent);
      } else {
        throw new Error('No transport available for message dispatch');
      }

      // Add to pending messages for receipt tracking
      this.messageHandler!.addMessageToPending(secureMessage);
      
      console.log(`Message ${secureMessage.id} dispatched to ${recipientId}`);
    } catch (error) {
      console.error('Failed to dispatch message:', error);
      throw error;
    }
  }

  private determineSecurityLevel(metadata: MessageMetadata): SecurityLevel {
    // Determine security level based on message metadata and session state
    if (metadata.requiresQuantumResistance) {
      return SecurityLevel.MAXIMUM;
    }
    if (metadata.useHeaderEncryption) {
      return SecurityLevel.ENHANCED;
    }
    return SecurityLevel.ESSENTIAL;
  }

  /**
   * Attempts to send messages from this client's own offline queue 
   * if the recipient peers are now online.
   * Should be called on startup or reconnection events.
   */
  async syncOutgoingOfflineMessages(): Promise<void> {
    this.ensureInitialized();
    console.log('Attempting to sync outgoing offline messages...');
    
    // Get all unique recipient IDs from the queue to avoid redundant peer checks
    // This assumes offlineMessageQueue can provide such a list or we iterate through all messages.
    // For simplicity, let's iterate all messages and check peer status per message, 
    // though batching by recipientId would be more efficient.

    const allQueuedMessages: { recipientId: string, messages: StoredMessage[] }[] = [];
    // This is a bit inefficient. If OfflineMessageQueue had a method like getAllMessagesGroupedByRecipient()
    // or getAllRecipientIdsWithPendingMessages() it would be better.
    // For now, we'll just iterate all stored messages to find recipients.
    // This part needs access to the internal structure of OfflineMessageQueue or a new method there.
    // Let's assume we add a method `getAllMessages` to OfflineMessageQueue for now.
    
    // To avoid direct access to offlineMessageQueue internals, we'd need a method like:
    // const pendingMessagesPerRecipient = await this.offlineMessageQueue.getAllGroupedByRecipient();
    // For now, we can't implement this loop without modifying OfflineMessageQueue or making assumptions.

    // Let's assume `OfflineMessageQueue` has a method `getAllMessagesFlat(): StoredMessage[]` for simplicity now
    // Or better: iterate recipients first

    // Get all recipient IDs that have messages queued.
    // This would ideally be a method on OfflineMessageQueue e.g. getRecipientIdsWithPendingMessages()
    // For now, we cannot implement this part without changing OfflineMessageQueue.
    // Let's defer the full implementation of iterating messages until OfflineMessageQueue is enhanced,
    // or simplify the logic to fetch all messages and then process.

    // Simplification: Get all messages and process one by one. This is less efficient for isPeerOnline checks.
    // This requires a new method in OfflineMessageQueue: getAllMessages(): StoredMessage[]
    // Let's assume OfflineMessageQueue.getAllMessagesFlat() exists for the purpose of this draft.
    // We will need to add this method to OfflineMessageQueue class later.

    // console.warn('syncOutgoingOfflineMessages requires OfflineMessageQueue.getAllMessagesFlat() or similar method to be implemented.');
    // For the sake of progress, let's imagine we have the messages for a specific recipient for now.
    // This part of the code would be better if we had a list of all recipient IDs with pending messages.

    const recipientIdsWithPending = await this.offlineMessageQueue.getAllRecipientIds();

    for (const recipientId of recipientIdsWithPending) {
      if (await this.isPeerOnline(recipientId)) {
        const messagesForRecipient = await this.offlineMessageQueue.getPendingFor(recipientId);
        console.log(`Peer ${recipientId} is now online. Attempting to send ${messagesForRecipient.length} queued messages.`);
        for (const storedMessage of messagesForRecipient) {
          try {
            // Reconstruct SecureMessage for dispatching
            // We need senderId for SecureMessage metadata, which we added to StoredMessage
            const secureMessage: SecureMessage = {
              id: storedMessage.messageId,
              encryptedContent: storedMessage.ciphertext,
              metadata: storedMessage.originalMetadata, // Use the stored original metadata
              protocolVersion: this.getProtocolVersion() // Assuming current version is fine for resending
            };
            
            await this.dispatchSecureMessage(recipientId, secureMessage);
            await this.offlineMessageQueue.remove(storedMessage.messageId);
            console.log(`Successfully sent queued message ${storedMessage.messageId} to ${recipientId}`);
          } catch (error) {
            console.error(`Failed to send queued message ${storedMessage.messageId} to ${recipientId}:`, error);
            // Optionally, increment deliveryAttempts in StoredMessage and re-store, or handle error differently.
            const messageToUpdate = await this.offlineMessageQueue.getMessageById(storedMessage.messageId);
            if (messageToUpdate) {
              messageToUpdate.deliveryAttempts++;
              // await this.offlineMessageQueue.store(messageToUpdate); // Re-storing might need an update method or remove+add
              console.log(`Incremented delivery attempts for ${messageToUpdate.messageId} to ${messageToUpdate.deliveryAttempts}`);
            }
          }
        }
      } else {
        console.log(`Peer ${recipientId} is still offline. Messages will remain queued.`);
      }
    }
    console.log('Finished attempting to sync outgoing offline messages.');
  }
  
  /**
   * Handles a bundle of messages received from a peer that were stored offline for this client.
   * This is part of the peer-based store-and-forward mechanism.
   */
  async handleIncomingOfflineMessageBundle(messages: StoredMessage[]): Promise<void> {
    this.ensureInitialized();
    console.log(`Received a bundle of ${messages.length} offline messages.`);
    for (const message of messages) {
      if (message.recipientId !== this.userId) {
        console.warn(`Received offline message ${message.messageId} not intended for this user (${this.userId}). Skipping.`);
        continue;
      }
      
      const processedMessage = await this.messageHandler!.processOfflineMessage(
        message.messageId,
        message.senderId,
        message.ciphertext,
        message.originalMetadata
      );

      if (processedMessage) {
        // TODO: Application layer should be notified about processedMessage.content, processedMessage.metadata, processedMessage.type
        console.log(`Successfully processed and handled incoming offline message ${message.messageId} from ${message.senderId}.`);
        // After successful processing by SecureMessageHandler, the peer that stored it should be notified (if applicable in the protocol)
        // so they can remove it from their queue. For now, we assume this client fetched it or it was pushed.
      } else {
        console.log(`Incoming offline message ${message.messageId} from ${message.senderId} was not processed (e.g., duplicate or error).`);
      }
    }
  }

  /**
   * Sends a Verifiable Credential to a peer.
   * @param chatId The context of the chat/session.
   * @param recipientDid The DID of the recipient.
   * @param vc The Verifiable Credential to send.
   * @param priority The priority of the message.
   * @returns {Promise<string>} The ID of the sent message.
   * @throws Error if service is not initialized or message preparation fails.
   */
  async sendVerifiableCredential(
    chatId: string,
    recipientDid: string, 
    vc: VerifiableCredential,
    priority: MessagePriority = MessagePriority.NORMAL
  ): Promise<string> {
    this.ensureInitialized();
    if (!this.messageHandler) {
      throw new Error('Message handler not available in MessageService.');
    }
    if (!this.issuedVcStore) {
        throw new Error('IssuedVcStore not available in MessageService.');
    }

    try {
      // Store the VC locally first
      await this.issuedVcStore.storeIssuedVc(vc);
      console.log(`Stored issued VC ID: ${vc.id || 'N/A'} locally before sending.`);

      const vcJson = JSON.stringify(vc);
      const vcBytes = new TextEncoder().encode(vcJson);

      // Use prepareBinaryMessage as it handles Uint8Array payloads
      const secureMessage = await this.messageHandler.prepareBinaryMessage(
        chatId,
        recipientDid,
        vcBytes,
        MessageType.VERIFIABLE_CREDENTIAL,
        {
          contentType: 'application/vc+json', // Standard MIME type for VCs
          priority,
          customData: { vcId: vc.id || 'unknown' } // Optional: add VC ID to customData for easier tracking
        }
      );

      await this.dispatchSecureMessage(recipientDid, secureMessage);
      console.log(`Verifiable Credential sent: ${secureMessage.id} to ${recipientDid}`);
      return secureMessage.id;
    } catch (error) {
      const errMessage = error instanceof Error ? error.message : String(error);
      console.error(`Failed to send Verifiable Credential to ${recipientDid}: ${errMessage}`);
      throw new MessageError(
        `Failed to send Verifiable Credential: ${errMessage}`,
        'VC_SEND_FAILED'
      );
    }
  }

  /**
   * Request offline messages from a peer (send OFFLINE_BUNDLE_REQUEST)
   */
  async requestOfflineMessagesFromPeer(peerId: string): Promise<void> {
    this.ensureInitialized();
    const request = {
      type: OfflineSyncMessageType.OFFLINE_BUNDLE_REQUEST,
      requesterId: this.userId
    };
    // Send request over P2P transport (assume a sendControlMessage method or similar exists)
    if (this.transport && typeof this.transport.sendControlMessage === 'function') {
      await this.transport.sendControlMessage(peerId, request);
    } else {
      console.warn('P2P transport does not support sendControlMessage. Implement this for full offline sync.');
    }
  }

  /**
   * Handle incoming OFFLINE_BUNDLE_REQUEST from a peer
   */
  async handleOfflineBundleRequest(requesterId: string): Promise<void> {
    this.ensureInitialized();
    // Get all pending messages for the requester
    const messages = await this.offlineMessageQueue.getPendingFor(requesterId);
    if (!messages.length) return;
    const response = {
      type: OfflineSyncMessageType.OFFLINE_BUNDLE_RESPONSE,
      recipientId: requesterId,
      messages
    };
    if (this.transport && typeof this.transport.sendControlMessage === 'function') {
      await this.transport.sendControlMessage(requesterId, response);
    } else {
      console.warn('P2P transport does not support sendControlMessage. Implement this for full offline sync.');
    }
  }

  /**
   * Handle incoming OFFLINE_BUNDLE_RESPONSE (bundle of messages)
   */
  async handleOfflineBundleResponse(messages: StoredMessage[]): Promise<void> {
    await this.handleIncomingOfflineMessageBundle(messages);
  }

  /**
   * Register handlers for offline sync control messages
   * Should be called after transport is initialized
   */
  registerOfflineSyncHandlers(): void {
    if (!this.transport || typeof this.transport.onControlMessage !== 'function') {
      console.warn('P2P transport does not support onControlMessage. Implement this for full offline sync.');
      return;
    }
    this.transport.onControlMessage(async (peerId: string, message: any) => {
      if (message.type === OfflineSyncMessageType.OFFLINE_BUNDLE_REQUEST) {
        await this.handleOfflineBundleRequest(peerId);
      } else if (message.type === OfflineSyncMessageType.OFFLINE_BUNDLE_RESPONSE) {
        if (Array.isArray(message.messages)) {
          await this.handleOfflineBundleResponse(message.messages);
        }
      }
    });
  }

  /**
   * Register handlers for PQC key exchange and protocol error control messages
   * Should be called after transport is initialized
   */
  registerPqcKeyExchangeHandlers(): void {
    if (!this.transport || typeof this.transport.onControlMessage !== 'function') {
      console.warn('P2P transport does not support onControlMessage. Implement this for full PQC key exchange.');
      return;
    }
    this.transport.onControlMessage(async (peerId: string, message: any) => {
      if (message.type === PqcKeyExchangeMessageType.PQC_PUBLIC_KEY_REQUEST) {
        await this.handlePqcPublicKeyRequest(peerId);
      } else if (message.type === PqcKeyExchangeMessageType.PQC_PUBLIC_KEY_RESPONSE) {
        await this.handlePqcPublicKeyResponse(peerId, message.pqcPublicKey);
      } else if (message.type === PqcKeyExchangeMessageType.PQC_KEM_ACK) {
        await this.handlePqcKemAck(peerId, message.chatId);
      } else if (message.type === PqcKeyExchangeMessageType.PQC_KEM_ERROR) {
        await this.handlePqcKemError(peerId, message.chatId, message.error);
      } else if (message.type === PqcKeyExchangeMessageType.PROTOCOL_ERROR) {
        await this.handleProtocolError(peerId, message.chatId, message.error);
      }
    });
  }

  /**
   * Request a peer's PQC public key
   */
  async requestPeerPqcPublicKey(peerId: string): Promise<void> {
    this.ensureInitialized();
    // Construct and send a PQC public key request message
    const requestMessage = {
      type: PqcKeyExchangeMessageType.PQC_PUBLIC_KEY_REQUEST,
      requesterId: this.userId
    };
    if (this.transport && typeof this.transport.sendControlMessage === 'function') {
      await this.transport.sendControlMessage(peerId, requestMessage);
      console.log(`PQC public key request sent to ${peerId}`);
    } else {
      console.warn('Transport does not support sendControlMessage. Implement this for full PQC key exchange.');
    }
  }

  /**
   * Handle an incoming PQC public key request
   */
  async handlePqcPublicKeyRequest(senderId: string): Promise<void> {
    this.ensureInitialized();
    if (!this.ownPqcPublicKeyId || !this.crypto) {
      console.error('Cannot respond to PQC public key request: PQC public key not available.');
      return;
    }
    const pqcPublicKeyBytes = await this.crypto.keyManager.getKey(this.ownPqcPublicKeyId);
    if (!pqcPublicKeyBytes) {
      console.error('Failed to retrieve own PQC public key bytes for response.');
      return;
    }
    const responseMessage = {
      type: PqcKeyExchangeMessageType.PQC_PUBLIC_KEY_RESPONSE,
      responderId: this.userId,
      pqcPublicKey: Array.from(pqcPublicKeyBytes) // Use Array for JSON serialization
    };
    if (this.transport && typeof this.transport.sendControlMessage === 'function') {
      await this.transport.sendControlMessage(senderId, responseMessage);
      console.log(`PQC public key response sent to ${senderId}`);
    } else {
      console.warn('Transport does not support sendControlMessage. Implement this for full PQC key exchange.');
    }
  }

  /**
   * Handle an incoming PQC public key response
   */
  async handlePqcPublicKeyResponse(senderId: string, pqcPublicKey: number[]): Promise<void> {
    this.ensureInitialized();
    // Store the received PQC public key for the peer
    if (!this.crypto) return;
    const pqcPublicKeyBytes = new Uint8Array(pqcPublicKey);
    await this.crypto.keyManager.storePeerPqcPublicKey(senderId, pqcPublicKeyBytes);
    console.log(`Stored PQC public key for peer ${senderId}`);
    // If there is a pending PQC session request for this peer, retry session establishment
    const pending = this.pendingPqcSessionRequests.get(senderId);
    if (pending) {
      this.pendingPqcSessionRequests.delete(senderId);
      console.log(`Retrying PQC session establishment with ${senderId} after receiving public key.`);
      await this.startSecureSession(pending.chatId, senderId, true, pending.negotiatedParams);
    }
  }

  /**
   * Send a protocol error control message to a peer
   * Used to signal protocol negotiation errors or out-of-order PQC KEM attempts.
   *
   * @param peerId - The peer to send the error to
   * @param chatId - The chat/session identifier
   * @param error - The error message
   */
  private async sendProtocolError(peerId: string, chatId: string, error: string): Promise<void> {
    if (!this.transport || typeof this.transport.sendControlMessage !== 'function') return;
    const errorMessage = {
      type: PqcKeyExchangeMessageType.PROTOCOL_ERROR,
      chatId,
      senderId: this.userId,
      error
    };
    await this.transport.sendControlMessage(peerId, errorMessage);
    console.log(`[PROTOCOL] Sent PROTOCOL_ERROR to ${peerId} for chat ${chatId}: ${error}`);
  }

  /**
   * Handler for protocol error control message
   * Logs and notifies listeners/UI of protocol negotiation errors.
   *
   * @param senderId - The peer who sent the error
   * @param chatId - The chat/session identifier
   * @param error - The error message
   */
  private async handleProtocolError(senderId: string, chatId: string, error: string): Promise<void> {
    // Log and notify UI or listeners
    console.error(`[PROTOCOL] Received PROTOCOL_ERROR from ${senderId} for chat ${chatId}: ${error}`);
    // TODO: Mark session/negotiation as failed, notify listeners/UI, etc.
  }

  private getFallbackTransport(securityLevel: SecurityLevel, failedTransport: Protocol): Protocol | null {
    const fallbackOrder: Record<SecurityLevel, Protocol[]> = {
      [SecurityLevel.MAXIMUM]: [Protocol.TOR, Protocol.MESH, Protocol.DIRECT],
      [SecurityLevel.ENHANCED]: [Protocol.MESH, Protocol.TOR, Protocol.DIRECT],
      [SecurityLevel.ESSENTIAL]: [Protocol.DIRECT, Protocol.MESH]
    };

    const fallbacks = fallbackOrder[securityLevel];
    const failedIndex = fallbacks.indexOf(failedTransport);
    
    if (failedIndex === -1 || failedIndex === fallbacks.length - 1) {
      return null;
    }

    const nextTransport = fallbacks[failedIndex + 1];
    const config = this.transportAdapter?.getTransportConfig(nextTransport);
    
    return config && config.enabled ? nextTransport : null;
  }
} 