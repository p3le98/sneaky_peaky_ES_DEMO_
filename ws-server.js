const WebSocket = require('ws');
const PORT = 8080;

const wss = new WebSocket.Server({ port: PORT });

// Keep track of clients with their IDs
const clients = new Map();

wss.on('connection', function connection(ws) {
  console.log('New client connected');
  let clientId = null;

  ws.on('message', function incoming(data) {
    try {
      const message = JSON.parse(data.toString());
      console.log('Message received:', {
        from: message.senderId,
        to: message.recipientId, 
        id: message.id
      });

      // Register client ID on first message
      if (!clientId && message.senderId) {
        clientId = message.senderId;
        clients.set(clientId, ws);
        console.log(`Client registered: ${clientId}`);
      }

      // Route message to specific recipient
      if (message.recipientId) {
        const recipientWs = clients.get(message.recipientId);
        if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
          recipientWs.send(data);
          console.log(`✅ Message routed from ${message.senderId} to ${message.recipientId}`);
        } else {
          console.log(`❌ Recipient ${message.recipientId} not found or not connected`);
          
          // For demo purposes: if specific routing fails, fallback to broadcast
          // This ensures the demo still works even if there are issues
          console.log('📡 Falling back to broadcast mode');
          wss.clients.forEach(function each(client) {
            if (client !== ws && client.readyState === WebSocket.OPEN) {
              client.send(data);
            }
          });
        }
      } else {
        // No recipient specified: broadcast to all other clients
        console.log('📡 Broadcasting to all clients');
        wss.clients.forEach(function each(client) {
          if (client !== ws && client.readyState === WebSocket.OPEN) {
            client.send(data);
          }
        });
      }
    } catch (error) {
      console.error('Error parsing message:', error);
      // Fallback: broadcast raw message for compatibility
      console.log('📡 Broadcasting raw message (parse error fallback)');
      wss.clients.forEach(function each(client) {
        if (client !== ws && client.readyState === WebSocket.OPEN) {
          client.send(data);
        }
      });
    }
  });

  ws.on('close', () => {
    if (clientId) {
      clients.delete(clientId);
      console.log(`Client disconnected: ${clientId}`);
    } else {
      console.log('Unknown client disconnected');
    }
  });

  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
  });
});

console.log(`✅ WebSocket server running at ws://localhost:${PORT}`);
console.log(`📱 Ready for DirectTransport demo testing`); 