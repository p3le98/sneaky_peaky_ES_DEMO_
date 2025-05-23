import { MessageService } from './src/messaging/message-service';
import { ReputationSystem } from './js/anti-abuse/reputation-system';
import { IssuedVcStore } from './src/identity/issued-vc-store';
import { MessagePriority } from './src/messaging/secure-message-handler';
import { SecurityLevel } from './src/core/security-levels';

// Initialize services
const reputationSystem = new ReputationSystem();
const issuedVcStore = new IssuedVcStore();

// Create message services for two users
const alice = new MessageService('alice', reputationSystem, issuedVcStore);
const bob = new MessageService('bob', reputationSystem, issuedVcStore);

// Initialize the services
async function initializeServices() {
  try {
    await alice.initialize({ requireQuantumResistance: true });
    await bob.initialize({ requireQuantumResistance: true });
    console.log('Services initialized successfully');
  } catch (error) {
    console.error('Failed to initialize services:', error);
  }
}

// Create a simple UI
function createUI() {
  const container = document.createElement('div');
  container.style.cssText = `
    max-width: 600px;
    margin: 20px auto;
    padding: 20px;
    font-family: Arial, sans-serif;
  `;

  // Create chat containers
  const aliceChat = document.createElement('div');
  aliceChat.style.cssText = `
    border: 1px solid #ccc;
    padding: 10px;
    margin-bottom: 20px;
    height: 300px;
    overflow-y: auto;
  `;
  aliceChat.id = 'alice-chat';

  const bobChat = document.createElement('div');
  bobChat.style.cssText = `
    border: 1px solid #ccc;
    padding: 10px;
    margin-bottom: 20px;
    height: 300px;
    overflow-y: auto;
  `;
  bobChat.id = 'bob-chat';

  // Create input fields
  const aliceInput = document.createElement('input');
  aliceInput.type = 'text';
  aliceInput.placeholder = 'Alice: Type a message...';
  aliceInput.style.cssText = `
    width: 70%;
    padding: 8px;
    margin-right: 10px;
  `;

  const bobInput = document.createElement('input');
  bobInput.type = 'text';
  bobInput.placeholder = 'Bob: Type a message...';
  bobInput.style.cssText = `
    width: 70%;
    padding: 8px;
    margin-right: 10px;
  `;

  // Create send buttons
  const aliceSend = document.createElement('button');
  aliceSend.textContent = 'Send';
  aliceSend.style.cssText = `
    padding: 8px 15px;
    background-color: #4CAF50;
    color: white;
    border: none;
    cursor: pointer;
  `;

  const bobSend = document.createElement('button');
  bobSend.textContent = 'Send';
  bobSend.style.cssText = `
    padding: 8px 15px;
    background-color: #4CAF50;
    color: white;
    border: none;
    cursor: pointer;
  `;

  // Add event listeners
  aliceSend.addEventListener('click', () => sendMessage(alice, bob, aliceInput.value, aliceChat));
  bobSend.addEventListener('click', () => sendMessage(bob, alice, bobInput.value, bobChat));

  // Append elements
  container.appendChild(document.createElement('h2')).textContent = 'Alice\'s Chat';
  container.appendChild(aliceChat);
  const aliceInputContainer = document.createElement('div');
  aliceInputContainer.appendChild(aliceInput);
  aliceInputContainer.appendChild(aliceSend);
  container.appendChild(aliceInputContainer);

  container.appendChild(document.createElement('h2')).textContent = 'Bob\'s Chat';
  container.appendChild(bobChat);
  const bobInputContainer = document.createElement('div');
  bobInputContainer.appendChild(bobInput);
  bobInputContainer.appendChild(bobSend);
  container.appendChild(bobInputContainer);

  document.body.appendChild(container);
}

// Function to send messages
async function sendMessage(
  sender: MessageService,
  recipient: MessageService,
  message: string,
  chatContainer: HTMLElement
) {
  if (!message.trim()) return;

  try {
    // Create a unique chat ID for this conversation
    const chatId = 'demo-chat-1';

    // Send the message
    const messageId = await sender.sendMessage(
      chatId,
      'bob', // Using hardcoded IDs since userId is private
      message,
      MessagePriority.NORMAL,
      {
        selfDestruct: false,
        destructionTimeMs: undefined
      }
    );

    // Add message to UI
    const messageElement = document.createElement('div');
    messageElement.style.cssText = `
      margin: 5px 0;
      padding: 8px;
      background-color: #e3f2fd;
      border-radius: 5px;
    `;
    messageElement.textContent = `${sender === alice ? 'alice' : 'bob'}: ${message}`;
    chatContainer.appendChild(messageElement);
    chatContainer.scrollTop = chatContainer.scrollHeight;

    // Simulate message reception
    setTimeout(async () => {
      try {
        const decryptedMessage = await recipient.receiveMessage(
          chatId,
          sender === alice ? 'alice' : 'bob',
          new Uint8Array(), // In a real app, this would be the encrypted message
          {
            priority: MessagePriority.NORMAL,
            securityLevel: SecurityLevel.ESSENTIAL
          }
        );

        // Add received message to recipient's chat
        const receivedElement = document.createElement('div');
        receivedElement.style.cssText = `
          margin: 5px 0;
          padding: 8px;
          background-color: #f5f5f5;
          border-radius: 5px;
        `;
        receivedElement.textContent = `${sender === alice ? 'alice' : 'bob'}: ${decryptedMessage}`;
        document.getElementById(`${recipient === alice ? 'alice' : 'bob'}-chat`)?.appendChild(receivedElement);
      } catch (error) {
        console.error('Error receiving message:', error);
      }
    }, 1000);

  } catch (error) {
    console.error('Error sending message:', error);
  }
}

// Initialize the demo
async function initDemo() {
  await initializeServices();
  createUI();
}

// Start the demo when the page loads
window.addEventListener('load', initDemo); 