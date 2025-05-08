const WebSocket = require('ws');
const express = require('express');
const http = require('http');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sanitizeHtml = require('sanitize-html');
const rateLimit = require('express-rate-limit');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const db = new sqlite3.Database('.data/users.db', (err) => {
    if (err) console.error('Database error:', err);
    db.run('CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)');
});

const jwtSecret = process.env.JWT_SECRET;
const adminKey = process.env.ADMIN_KEY;
const admins = new Set();

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: 'Too many login attempts. Please try again later.'
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/register', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.json({ error: 'Username and password required' });
    }
    const sanitizedUsername = sanitizeHtml(username);
    if (sanitizedUsername !== username || username.length < 3) {
        return res.json({ error: 'Invalid username' });
    }
    if (password.length < 6) {
        return res.json({ error: 'Password must be at least 6 characters' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run('INSERT INTO users (username, password) VALUES (?, ?)', [sanitizedUsername, hashedPassword], (err) => {
            if (err) {
                return res.json({ error: 'Username already exists' });
            }
            const token = jwt.sign({ username: sanitizedUsername }, jwtSecret, { expiresIn: '1h' });
            res.json({ token });
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.json({ error: 'Server error' });
    }
});

app.post('/login', loginLimiter, (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.json({ error: 'Username and password required' });
    }
    const sanitizedUsername = sanitizeHtml(username);
    db.get('SELECT password FROM users WHERE username = ?', [sanitizedUsername], async (err, row) => {
        if (err || !row) {
            return res.json({ error: 'Invalid username or password' });
        }
        const match = await bcrypt.compare(password, row.password);
        if (!match) {
            return res.json({ error: 'Invalid username or password' });
        }
        const token = jwt.sign({ username: sanitizedUsername }, jwtSecret, { expiresIn: '1h' });
        res.json({ token });
    });
});

let servers = [];
const clients = new Map();

wss.on('connection', ws => {
    clients.set(ws, { userId: null, servers: new Set(), token: null });

    ws.on('message', message => {
        let data;
        try {
            data = JSON.parse(message);
        } catch (error) {
            console.error('Invalid message:', error);
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid message format' }));
            return;
        }

        if (!data.userId || !data.token) {
            ws.send(JSON.stringify({ type: 'error', message: 'Authentication required' }));
            return;
        }

        try {
            const decoded = jwt.verify(data.token, jwtSecret);
            if (decoded.username !== data.userId) {
                ws.send(JSON.stringify({ type: 'error', message: 'Invalid token' }));
                return;
            }
        } catch (error) {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid token' }));
            return;
        }

        clients.get(ws).userId = data.userId;
        clients.get(ws).token = data.token;

        switch (data.type) {
            case 'getServers':
                ws.send(JSON.stringify({ type: 'servers', servers }));
                break;
            case 'createServer':
                if (!data.id || !data.name || !data.maxUsers) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Server ID, name, and max users required' }));
                    return;
                }
                const sanitizedName = sanitizeHtml(data.name);
                if (sanitizedName !== data.name) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Invalid server name' }));
                    return;
                }
                servers.push({ id: data.id, name: sanitizedName, creator: data.userId, maxUsers: data.maxUsers, users: [data.userId] });
                broadcastServers();
                break;
            case 'deleteServer':
                const serverIndex = servers.findIndex(server => server.id === data.id);
                if (serverIndex === -1) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Server not found' }));
                    return;
                }
                if (servers[serverIndex].creator !== data.userId && !admins.has(data.userId)) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Only the creator or an admin can delete this server' }));
                    return;
                }
                servers.splice(serverIndex, 1);
                broadcastServers();
                clients.forEach(client => {
                    if (client.servers.has(data.id)) {
                        client.send(JSON.stringify({ type: 'forceLeave', serverId: data.id }));
                    }
                });
                break;
            case 'join':
                const server = servers.find(s => s.id === data.serverId);
                if (!server) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Server not found' }));
                    return;
                }
                if (server.users.length >= server.maxUsers) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Server is full' }));
                    return;
                }
                if (!server.users.includes(data.userId)) {
                    server.users.push(data.userId);
                    clients.get(ws).servers.add(data.serverId);
                    broadcastServers();
                    broadcastToServer(data.serverId, data, ws);
                    broadcastParticipantList(data.serverId);
                }
                break;
            case 'leave':
                const leaveServer = servers.find(s => s.id === data.serverId);
                if (leaveServer) {
                    leaveServer.users = leaveServer.users.filter(userId => userId !== data.userId);
                    clients.get(ws).servers.delete(data.serverId);
                    broadcastServers();
                    broadcastToServer(data.serverId, data, ws);
                    broadcastParticipantList(data.serverId);
                }
                break;
            case 'kick':
                if (!admins.has(data.userId)) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Admin privileges required to kick participants' }));
                    return;
                }
                const kickServer = servers.find(s => s.id === data.serverId);
                if (!kickServer) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Server not found' }));
                    return;
                }
                if (data.userId === data.targetUserId) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Cannot kick yourself' }));
                    return;
                }
                kickServer.users = kickServer.users.filter(userId => userId !== data.targetUserId);
                broadcastServers();
                broadcastToServer(data.serverId, { type: 'forceLeave', serverId: data.serverId, userId: data.targetUserId }, ws);
                broadcastParticipantList(data.serverId);
                break;
            case 'forceMute':
                if (!admins.has(data.userId)) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Admin privileges required to force mute participants' }));
                    return;
                }
                const muteServer = servers.find(s => s.id === data.serverId);
                if (!muteServer) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Server not found' }));
                    return;
                }
                if (data.userId === data.targetUserId) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Cannot force mute yourself' }));
                    return;
                }
                broadcastToServer(data.serverId, { type: 'forceMute', serverId: data.serverId, userId: data.targetUserId, isMuted: data.isMuted }, ws);
                break;
            case 'adminAuth':
                if (data.key === adminKey) {
                    admins.add(data.userId);
                    ws.send(JSON.stringify({ type: 'adminAuth', success: true }));
                } else {
                    ws.send(JSON.stringify({ type: 'adminAuth', success: false, message: 'Invalid admin key' }));
                }
                break;
            case 'getParticipants':
                const participantServer = servers.find(s => s.id === data.serverId);
                if (participantServer) {
                    ws.send(JSON.stringify({
                        type: 'participantList',
                        serverId: data.serverId,
                        participants: participantServer.users,
                        host: participantServer.creator
                    }));
                }
                break;
            case 'offer':
            case 'answer':
            case 'candidate':
            case 'chat':
            case 'volume':
            case 'mute':
            case 'video':
                if (!data.serverId) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Server ID required' }));
                    return;
                }
                data.text = data.text ? sanitizeHtml(data.text) : data.text;
                clients.get(ws).servers.add(data.serverId);
                broadcastToServer(data.serverId, data, ws);
                break;
            default:
                ws.send(JSON.stringify({ type: 'error', message: 'Unknown message type' }));
        }
    });

    ws.on('close', () => {
        const userId = clients.get(ws).userId;
        const userServers = new Set(clients.get(ws).servers);
        userServers.forEach(serverId => {
            const server = servers.find(s => s.id === serverId);
            if (server) {
                server.users = server.users.filter(id => id !== userId);
                broadcastToServer(serverId, {
                    type: 'leave',
                    serverId,
                    userId,
                    token: clients.get(ws).token
                }, ws);
                broadcastParticipantList(serverId);
            }
        });
        admins.delete(userId);
        clients.delete(ws);
        broadcastServers();
    });
});

function broadcastServers() {
    const message = JSON.stringify({ type: 'servers', servers });
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(message);
        }
    });
}

function broadcastToServer(serverId, data, sender) {
    wss.clients.forEach(client => {
        if (client !== sender && client.readyState === WebSocket.OPEN) {
            const clientData = clients.get(client);
            if (clientData.servers.has(serverId)) {
                client.send(JSON.stringify(data));
            }
        }
    });
}

function broadcastParticipantList(serverId) {
    const server = servers.find(s => s.id === serverId);
    if (server) {
        const message = JSON.stringify({
            type: 'participantList',
            serverId,
            participants: server.users,
            host: server.creator
        });
        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN && clients.get(client).servers.has(serverId)) {
                client.send(message);
            }
        });
    }
}

server.listen(process.env.PORT || 8080, () => {
    console.log(`Server running on port ${process.env.PORT || 8080}`);
});
