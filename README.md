# Sneaky Peaky – Essential Tier Demo

This is a simple demo of the “Essential” tier of **Sneaky Peaky**, a privacy-first messaging system. It lets two people on the same local network send end-to-end encrypted messages using WebSockets and AES-GCM encryption.

This demo is intended for testing purposes — it's not production-grade — and it focuses on the core communication between two PCs.

---

##  What’s included

- Real-time messaging between two browser clients
- AES-GCM encryption using the Web Crypto API
- Fixed client IDs (`client_A` and `client_B`)
- A custom WebSocket server with routing and fallback
- A lightweight UI to send and receive messages

---

##  How to run the demo (between two PCs)

### 1. Clone this repository

```bash
git clone https://github.com/p3le98/sneaky_peaky_ES_DEMO_.git
cd sneaky_peaky_ES_DEMO_
````

### 2. Install the dependencies

```bash
npm install
```

### 3. Start the WebSocket server

Run this on **one** of the two machines (the host server):

```bash
node ws-server.js
```

You should see:

```
✅ WebSocket server running at ws://localhost:8080
📱 Ready for DirectTransport demo testing
```

---

### 4. Find the server PC’s local IP address

Run `ipconfig` (on Windows) or `ifconfig` (on macOS/Linux) and look for an IP like `192.168.x.x`.

---

### 5. Update the `serverUrl` in the client code

In your `demo.ts` (or `direct-transport.ts`), find the `serverUrl` and replace it:

```ts
serverUrl: 'ws://192.168.x.x:8080' // Replace with the real IP from Step 4
```

---

### 6. Run the demo in two browsers

Open the demo on both PCs:

* On the **first PC**, enter `client_A` when prompted
* On the **second PC**, enter `client_B`

You should now be able to send messages securely between the two machines.

---

## Encryption

All messages are encrypted using AES-GCM through the browser’s Web Crypto API.

* Messages are encrypted with a shared symmetric key
* The WebSocket server doesn’t know or log decrypted message contents
* Messages include proper IV handling per AES-GCM standards

---

## How the server works

* Each client identifies itself with a fixed ID (`client_A`, `client_B`)
* The WebSocket server keeps track of active clients
* Messages are routed directly if the recipient is connected
* If direct routing fails, the server falls back to broadcasting the message

---

##  What this demo does *not* include

This demo is minimal by design. It does **not** yet include:

* Identity verification
* Key exchange protocols
* Message authentication (MACs/signatures)
* Post-quantum encryption
* Tor, I2P, or mesh transport

These are planned for future security tiers in Sneaky Peaky.

---

## Why this exists

This demo is part of an ongoing project to build a full privacy-first, decentralized, open-source messaging system. This “Essential” tier helps verify that direct encrypted messaging works before layering on more advanced security and routing.

---

## Credits

Built with love and obsession by [@p3le98](https://github.com/p3le98).
Core architecture guided by months of planning, testing, and debugging — and supported with occasional help from ChatGPT, Claude (3.7/4) and Cursor code editor.

---

## Questions?

If you run into issues or want to contribute, feel free to open an issue or contact the repo owner.

```

---
