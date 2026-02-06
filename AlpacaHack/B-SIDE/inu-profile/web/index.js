import crypto from 'node:crypto';
import fs from 'node:fs/promises';

import fastify from 'fastify';
import fastifyCookie from '@fastify/cookie';
import fastifySession from '@fastify/session';

const PORT = process.env.PORT || 3000;
const FLAG = process.env.FLAG || 'Alpaca{DUMMY}';

const app = fastify();
app.register(fastifyCookie);
app.register(fastifySession, {
    secret: crypto.randomBytes(16).toString('hex'),
    cookie: { secure: false }
});

const DEFAULT_PROFILE = {
    'avatar': '\u{1f436}',
    'description': 'bow wow!'
};

let users = {
    admin: {
        password: crypto.randomBytes(16).toString('hex'),
        avatar: '\u{1f32d}',
        description: 'I am admin!'
    }
};

const indexHtml = await fs.readFile('./index.html');
app.get('/', async (req, res) => {
    return res.type('text/html').send(indexHtml);
});

// become admin to get the flag!
app.get('/admin', async (req, res) => {
    const { username } = req.session;
    if (!req.session.hasOwnProperty('username') || username !== 'admin') {
        return res.send({ 'message': 'you are not an admin...' });
    }

    return res.send({ 'message': `Congratulations! The flag is: ${FLAG}` });
});

// omit credentials
function getFilteredProfile(username) {
    const profile = users[username];
    const filteredProfile = Object.entries(profile).filter(([k]) => {
        return k in DEFAULT_PROFILE; // default profile has the key, so we can expose this key
    });
    
    return Object.fromEntries(filteredProfile);
}

app.get('/profile', async (req, res) => {
    const { username } = req.session;
    if (username == null) {
        return res.send({ 'message': 'please log in' });
    }

    return res.send(getFilteredProfile(username));
});

app.get('/profile/:username', async (req, res) => {
    const { username } = req.params;

    if (!users.hasOwnProperty(username)) {
        return res.send({ 'message': `${username} does not exist` });
    }

    return res.send(getFilteredProfile(username));
});

app.post('/register', async (req, res) => {
    const { username, password, profile } = req.body;

    if (username == null || password == null || profile == null) {
        return res.send({ 'message': `username, password, or profile is not provided` });
    }

    // no hack, please
    if (typeof username !== 'string' || typeof password !== 'string') {
        return res.send({ 'message': 'what are you doing?' });
    }

    if (users.hasOwnProperty(username)) {
        return res.send({ 'message': `${username} is already registered` });
    }

    // set default value for some keys if the profile given doesn't have it
    users[username] ??= { password, ...DEFAULT_PROFILE };

    // okay, let's update the database
    for (const key in profile) {
        users[username][key] = profile[key];
    };

    req.session.username = username;
    return res.send({ 'message': 'ok' });
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (username == null || password == null) {
        return res.send({ 'message': `username, or password is not provided` });
    }

    // no hack, please
    if (typeof username !== 'string' || typeof password !== 'string') {
        return res.send({ 'message': 'what are you doing?' });
    }

    if (!users.hasOwnProperty(username)) {
        return res.send({ 'message': `${username} does not exist` });
    }

    if (users[username].password !== password) {
        return res.send({ 'message': 'password does not match' });
    }

    req.session.username = username;
    return res.send({ 'message': 'ok' });
});

app.listen({ port: PORT, host: '0.0.0.0' }, (err, address) => {
    if (err) {
        console.error(err);
        process.exit(1);
    }
    console.log(`server listening on ${address}`);
});