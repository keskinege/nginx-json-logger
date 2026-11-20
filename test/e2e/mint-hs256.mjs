import crypto from 'crypto';
import fs from 'fs';

const args = process.argv.slice(2);
function arg(name, def) {
    const i = args.indexOf('--' + name);
    return i === -1 ? def : args[i + 1];
}

function demoSecret() {
    try {
        const file = new URL('../../deploy/kubernetes/jwks.json', import.meta.url);
        const k = JSON.parse(fs.readFileSync(file, 'utf8')).keys[0].k;
        return Buffer.from(k, 'base64url').toString('utf8');
    } catch (e) { return ''; }
}

const now = Math.floor(Date.now() / 1000);
const header = { alg: 'HS256', typ: 'JWT', kid: '0001' };
const payload = {
    iss: arg('iss', 'https://dummy-idp.local'),
    sub: arg('sub', 'alice'),
    aud: arg('aud', 'api'),
    roles: ['devops'],
    iat: now,
    exp: now + Number(arg('exp-in', '3600')),
    jti: arg('jti', 'test-' + now),
};
const secret = arg('secret', process.env.JWT_SECRET || demoSecret());
if (!secret) {
    console.error('no demo key: pass --secret or set JWT_SECRET');
    process.exit(2);
}

const b64 = (o) => Buffer.from(JSON.stringify(o), 'utf8').toString('base64url');
const signingInput = b64(header) + '.' + b64(payload);
const signature = crypto.createHmac('sha256', secret).update(signingInput).digest('base64url');

console.log(signingInput + '.' + signature);
