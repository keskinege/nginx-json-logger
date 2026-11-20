const now = Math.floor(Date.now() / 1000);
const header = { alg: 'RS256', typ: 'JWT', kid: 'local-log-only' };
const payload = {
    iss: 'http://localhost:8080/realms/jsonlog',
    sub: 'alice',
    aud: ['api'],
    scope: 'orders:read orders:write',
    realm_access: { roles: ['ops'] },
    groups: ['/staff'],
    iat: now,
    exp: now + 3600,
    jti: 'local-test',
};
const b64 = (o) => Buffer.from(JSON.stringify(o), 'utf8').toString('base64url');
console.log(`${b64(header)}.${b64(payload)}.c2lnbmF0dXJl`);
