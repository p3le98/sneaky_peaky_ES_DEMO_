import { Message, MessageSendResult } from './message-types';
import { HybridMessageSender } from './hybrid-message-sender';
import { Protocol } from '../core/protocol-types';
import { SecurityLevel } from '../core/security-levels';
import { TorService } from '../tor/tor-service';
import { MeshNetwork } from '../networks/mesh-network';
import { DirectTransport } from '../transport/direct-transport';

/**
 * Transport configuration for different protocols
 */
export interface TransportConfig {
  protocol: Protocol;
  enabled: boolean;
  maxMessageSize: number;
  requiresEncryption: boolean;
  supportsMetadata: boolean;
  priorityMapping: Record<string, number>;
}

/**
 * Adapts messages to different transport mechanisms
 */
export class TransportAdapter {
  private transportConfigs: Map<Protocol, TransportConfig> = new Map();
  
  constructor(
    private messageSender: HybridMessageSender,
    private torService: TorService,
    private meshNetwork: MeshNetwork,
    private directTransport: DirectTransport
  ) {
    // Initialize default transport configs
    this.initializeTransportConfigs();
  }
  
  /**
   * Sends a message through the appropriate transport
   * @param message The message to send
   * @returns Promise resolving to send result
   */
  async sendMessage(message: Message): Promise<MessageSendResult> {
    // Determine best transport based on message properties
    const transport = this.selectTransport(message);
    
    if (!transport) {
      return {
        success: false,
        error: 'No suitable transport available for this message'
      };
    }
    
    // Adapt message for the selected transport
    const adaptedMessage = this.adaptMessageForTransport(message, transport);
    
    try {
      // Send through hybrid message sender which handles fallbacks
      return await this.messageSender.sendMessage(adaptedMessage);
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error in transport'
      };
    }
  }
  
  /**
   * Selects the most appropriate transport for a message
   * @param message The message to send
   * @returns Selected transport config or null if none available
   */
  private selectTransport(message: Message): TransportConfig | null {
    // Start with a preference based on security level
    let preferredTransports: Protocol[] = [];
    
    switch (message.securityLevel) {
      case SecurityLevel.MAXIMUM:
        preferredTransports = [Protocol.TOR];
        break;
      case SecurityLevel.ENHANCED:
        preferredTransports = [Protocol.TOR, Protocol.MESH];
        break;
      case SecurityLevel.ESSENTIAL:
        preferredTransports = [Protocol.MESH, Protocol.DIRECT];
        break;
    }
    
    // Check each preferred transport in order
    for (const protocol of preferredTransports) {
      const config = this.transportConfigs.get(protocol);
      
      if (config && config.enabled) {
        // Check message size compatibility
        const messageSize = this.estimateMessageSize(message);
        if (messageSize <= config.maxMessageSize) {
          return config;
        }
      }
    }
    
    // If no preferred transport is suitable, try any enabled transport
    for (const config of this.transportConfigs.values()) {
      if (config.enabled) {
        const messageSize = this.estimateMessageSize(message);
        if (messageSize <= config.maxMessageSize) {
          return config;
        }
      }
    }
    
    // No suitable transport found
    return null;
  }
  
  /**
   * Adapts a message for a specific transport
   * @param message The original message
   * @param transport The transport configuration
   * @returns Adapted message for the transport
   */
  private adaptMessageForTransport(message: Message, transport: TransportConfig): Message {
    // Create a copy of the message to adapt
    const adaptedMessage = { ...message };
    
    // Add transport info to metadata
    if (!adaptedMessage.metadata) {
      adaptedMessage.metadata = {
        priority: message.priority,
        securityLevel: message.securityLevel
      };
    }
    
    if (!adaptedMessage.metadata.transportInfo) {
      adaptedMessage.metadata.transportInfo = {
        protocol: transport.protocol
      };
    } else {
      adaptedMessage.metadata.transportInfo.protocol = transport.protocol;
    }
    
    // Handle metadata limitations
    if (!transport.supportsMetadata && adaptedMessage.metadata) {
      // Preserve only essential metadata
      adaptedMessage.metadata = {
        priority: message.priority,
        securityLevel: message.securityLevel,
        expiresAt: adaptedMessage.metadata.expiresAt,
        ttl: adaptedMessage.metadata.ttl,
        transportInfo: adaptedMessage.metadata.transportInfo
      };
    }
    
    // Map message to transport format
    switch (transport.protocol) {
      case Protocol.TOR:
        return this.adaptForTor(adaptedMessage);
      case Protocol.MESH:
        return this.adaptForMesh(adaptedMessage);
      case Protocol.DIRECT:
        return this.adaptForDirect(adaptedMessage);
      default:
        return adaptedMessage;
    }
  }
  
  /**
   * Adapts a message for the Tor transport
   * @param message The message to adapt
   * @returns Tor-adapted message
   */
  private adaptForTor(message: Message): Message {
    const adapted = { ...message };
    
    // For Tor, we add onion routing information
    if (!adapted.metadata) {
      adapted.metadata = {
        priority: message.priority,
        securityLevel: message.securityLevel
      };
    }
    
    if (!adapted.metadata.transportInfo) {
      adapted.metadata.transportInfo = { protocol: Protocol.TOR };
    }
    
    // Add hops count if using Tor
    adapted.metadata.transportInfo.hops = 3; // Default Tor hops
    
    return adapted;
  }
  
  /**
   * Adapts a message for the Mesh transport
   * @param message The message to adapt
   * @returns Mesh-adapted message
   */
  private adaptForMesh(message: Message): Message {
    const adapted = { ...message };
    
    // For Mesh, we might add routing path information
    if (!adapted.metadata) {
      adapted.metadata = {
        priority: message.priority,
        securityLevel: message.securityLevel
      };
    }
    
    if (!adapted.metadata.transportInfo) {
      adapted.metadata.transportInfo = { protocol: Protocol.MESH };
    }
    
    return adapted;
  }
  
  /**
   * Adapts a message for direct transport
   * @param message The message to adapt
   * @returns Direct-adapted message
   */
  private adaptForDirect(message: Message): Message {
    const adapted = { ...message };
    
    // For direct transport, we'd generally strip out unnecessary overhead
    if (!adapted.metadata) {
      adapted.metadata = {
        priority: message.priority,
        securityLevel: message.securityLevel
      };
    }
    
    // Simplify metadata for direct transport
    adapted.metadata = {
      priority: message.priority,
      securityLevel: message.securityLevel,
      conversationId: adapted.metadata.conversationId,
      transportInfo: {
        protocol: Protocol.DIRECT
      }
    };
    
    return adapted;
  }
  
  /**
   * Initializes default transport configurations
   */
  private initializeTransportConfigs(): void {
    // Tor configuration
    this.transportConfigs.set(Protocol.TOR, {
      protocol: Protocol.TOR,
      enabled: true,
      maxMessageSize: 50 * 1024, // 50 KB
      requiresEncryption: true,
      supportsMetadata: true,
      priorityMapping: {
        HIGH: 1,
        NORMAL: 2,
        LOW: 3
      }
    });
    
    // Mesh configuration
    this.transportConfigs.set(Protocol.MESH, {
      protocol: Protocol.MESH,
      enabled: true,
      maxMessageSize: 100 * 1024, // 100 KB
      requiresEncryption: true,
      supportsMetadata: true,
      priorityMapping: {
        HIGH: 0,
        NORMAL: 1,
        LOW: 2
      }
    });
    
    // Direct configuration
    this.transportConfigs.set(Protocol.DIRECT, {
      protocol: Protocol.DIRECT,
      enabled: false, // Disabled by default for security
      maxMessageSize: 1024 * 1024, // 1 MB
      requiresEncryption: true,
      supportsMetadata: false,
      priorityMapping: {
        HIGH: 0,
        NORMAL: 0,
        LOW: 0
      }
    });
  }
  
  /**
   * Updates a transport configuration
   * @param protocol The protocol to update
   * @param config Configuration updates
   */
  updateTransportConfig(
    protocol: Protocol,
    config: Partial<TransportConfig>
  ): void {
    const currentConfig = this.transportConfigs.get(protocol);
    
    if (currentConfig) {
      this.transportConfigs.set(protocol, {
        ...currentConfig,
        ...config,
        protocol // Ensure protocol doesn't change
      });
    }
  }
  
  /**
   * Enables or disables a transport protocol
   * @param protocol The protocol to update
   * @param enabled Whether the protocol should be enabled
   */
  setTransportEnabled(protocol: Protocol, enabled: boolean): void {
    const config = this.transportConfigs.get(protocol);
    
    if (config) {
      config.enabled = enabled;
      this.transportConfigs.set(protocol, config);
    }
  }
  
  /**
   * Estimates the size of a message in bytes
   * @param message The message to measure
   * @returns Estimated size in bytes
   */
  private estimateMessageSize(message: Message): number {
    // Simplified estimation based on JSON serialization
    return JSON.stringify(message).length;
  }
  
  /**
   * Gets the current configuration for a transport
   * @param protocol The protocol to get configuration for
   * @returns Transport configuration or undefined if not found
   */
  getTransportConfig(protocol: Protocol): TransportConfig | undefined {
    return this.transportConfigs.get(protocol);
  }
  
  /**
   * Gets all available transports
   * @returns Array of transport configurations
   */
  getAllTransports(): TransportConfig[] {
    return Array.from(this.transportConfigs.values());
  }
} 