const express = require('express');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);

// Configured for cross-origin tracking from your Netlify production frontend
const io = new Server(server, {
    cors: {
        origin: "*", 
        methods: ["GET", "POST"]
    }
});

// Global infrastructure map: PIN -> Host Socket ID
const globalPINMap = new Map();

io.on('connection', (socket) => {
    console.log(`Node connected to coordination layer: ${socket.id}`);

    // Generate unique 4-digit passkey
    let pin;
    do {
        pin = Math.floor(1000 + Math.random() * 9000).toString();
    } while (globalPINMap.has(pin));

    globalPINMap.set(pin, socket.id);
    socket.emit('your-pin', pin);
    console.log(`Assigned PIN ${pin} to host connection: ${socket.id}`);

    // Handle incoming cross-platform join request matching a valid passkey
    socket.on('join-room', (targetPin) => {
        const hostSocketId = globalPINMap.get(targetPin);

        if (!hostSocketId) {
            socket.emit('error-message', 'PIN invalid or host instance offline.');
            return;
        }

        if (hostSocketId === socket.id) {
            socket.emit('error-message', 'Loopback restriction: Cannot connect to self.');
            return;
        }

        const activeRoomName = `global-room-${targetPin}`;
        
        // Force bind both client connections to the target WebRTC room
        socket.join(activeRoomName);
        const hostSocket = io.sockets.sockets.get(hostSocketId);
        if (hostSocket) {
            hostSocket.join(activeRoomName);
        }

        // Drop the used PIN immediately to safeguard the tunnel connection
        globalPINMap.delete(targetPin);

        // Signal both targets to execute WebRTC peer connection configuration
        io.to(activeRoomName).emit('peer-matched', { 
            roomName: activeRoomName,
            initiator: hostSocketId
        });
        console.log(`P2P Bridge successfully initialized for room: ${activeRoomName}`);
    });

    // Abstract WebRTC message routing (SDP Handshakes, ICE Network Paths)
    socket.on('signal', (data) => {
        if (data && data.roomName) {
            socket.to(data.roomName).emit('signal', data);
        }
    });

    // Housekeeping routine to purge dead allocation tokens
    socket.on('disconnect', () => {
        console.log(`Node dropped: ${socket.id}`);
        for (let [pin, id] of globalPINMap.entries()) {
            if (id === socket.id) {
                globalPINMap.delete(pin);
                break;
            }
        }
    });
});

// Base deployment health check endpoint for Railway live uptime verification
app.get('/', (req, res) => {
    res.send('P2P Global Signaling Engine Operational.');
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Signaling infrastructure deployment running on port ${PORT}`));