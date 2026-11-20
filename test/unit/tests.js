import jsonlog from '../../njs/jsonlog.js';
import { mockRequest, assert, eq } from './mock.js';

export const tests = [];
function test(name, fn) { tests.push({ name: name, fn: fn }); }

test('emit returns one line with required envelope fields', function () {
    const r = mockRequest({ vars: { time_iso8601: '2026-11-19T20:42:11+00:00', request_id: 'abc123', pid: '42' } });
    const line = jsonlog.emit(r);
    assert(line.indexOf('\n') === -1, 'record must be single-line');
    const rec = JSON.parse(line);
    eq(rec.schema_version, '1.0.0', 'schema_version');
    eq(rec.event, 'http_request', 'event');
    eq(rec.request_id, 'abc123', 'request_id');
    eq(typeof rec.ts, 'string', 'ts');
});

test('duplicate headers survive as arrays and credentials are redacted', async function () {
    const r = mockRequest({
        method: 'POST',
        uri: '/api/v1/orders',
        args: 'expand=items',
        rawIn: [
            ['Host', 'api.example.com'],
            ['Via', '1.1 alpha'],
            ['Via', '1.1 beta'],
            ['Authorization', 'Bearer abc.def.ghi'],
            ['Cookie', 'session=secret'],
            ['X-Empty', ''],
        ],
        vars: { time_iso8601: '2026-11-19T20:42:11+00:00', request_id: 'rid-1' },
    });
    await jsonlog.request(r);
    const meta = JSON.parse(r.variables.jl_req_meta);
    eq(meta.headers.via, ['1.1 alpha', '1.1 beta'], 'duplicate header');
    eq(meta.headers.authorization, '[REDACTED]', 'authorization redacted');
    eq(meta.headers.cookie, '[REDACTED]', 'cookie redacted');
    eq(meta.headers['x-empty'], '', 'empty header preserved');
    assert(meta.redactions.length >= 2, 'redactions recorded');
});

test('emit includes request, client, server, tls and timings sections', function () {
    const r = mockRequest({
        vars: {
            time_iso8601: '2026-11-19T20:42:11+00:00', request_id: 'rid-1',
            request_method: 'GET', request_uri: '/api/get?x=1', uri: '/api/get',
            args: 'x=1', server_protocol: 'HTTP/1.1', request: 'GET /api/get?x=1 HTTP/1.1',
            request_length: '120', host: 'localhost', server_name: 'localhost',
            server_addr: '172.18.0.2', server_port: '8080', scheme: 'http',
            remote_addr: '172.18.0.1', remote_port: '51234',
            connection: '9', connection_requests: '2', msec: '1763584931.221',
            pid: '42', request_time: '0.012', bytes_sent: '300', body_bytes_sent: '200',
            status: '200', sent_http_content_type: 'application/json',
        },
    });
    r.variables.jl_req_meta = JSON.stringify({ headers: { accept: '*/*' }, redactions: [] });
    const rec = JSON.parse(jsonlog.emit(r));
    eq(rec.request.method, 'GET', 'request.method');
    eq(rec.request.path, '/api/get', 'request.path');
    eq(rec.request.args, { x: '1' }, 'request.args parsed');
    eq(rec.request.raw_args, 'x=1', 'request.raw_args');
    eq(rec.client.remote_addr, '172.18.0.1', 'client.remote_addr');
    eq(rec.timings.request_s, 0.012, 'timings.request_s number');
    eq(rec.server.port, 8080, 'server.port number');
    eq(rec.tls.protocol, null, 'tls null over http');
});

function b64url(s) {
    return Buffer.from(s, 'utf8').toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function shapedToken(header, payload) {
    return b64url(JSON.stringify(header)) + '.' + b64url(JSON.stringify(payload)) + '.c2ln';
}

test('jwt decode exposes header, claims, derived values and local time checks', async function () {
    const now = Math.floor(Date.now() / 1000);
    const token = shapedToken(
        { alg: 'RS256', typ: 'JWT', kid: 'k1' },
        { iss: 'http://localhost:8080/realms/jsonlog', sub: 'user-1', aud: ['api'],
          exp: now + 600, iat: now - 10, scope: 'orders:read orders:write',
          realm_access: { roles: ['ops'] }, groups: ['/staff'] });
    const r = mockRequest({ rawIn: [['Authorization', 'Bearer ' + token]] });
    await jsonlog.request(r);
    const auth = JSON.parse(r.variables.jl_jwt);
    eq(auth.present, true, 'present');
    eq(auth.jwt.header.kid, 'k1', 'kid');
    eq(auth.jwt.claims.sub, 'user-1', 'sub');
    eq(auth.jwt.derived.scopes, ['orders:read', 'orders:write'], 'scopes');
    eq(auth.jwt.derived.roles, ['ops'], 'roles flattened');
    eq(auth.jwt.derived.groups, ['/staff'], 'groups');
    eq(auth.jwt.checks.exp_ok, true, 'exp_ok');
    assert(auth.jwt.fingerprint_sha256.length === 64, 'sha256 hex fingerprint');
    eq(auth.jwt.fingerprint_sha256.indexOf(token), -1, 'token not embedded');
});

test('malformed and missing tokens are recorded, never thrown', async function () {
    const bad = mockRequest({ rawIn: [['Authorization', 'Bearer not-a-jwt']] });
    await jsonlog.request(bad);
    eq(JSON.parse(bad.variables.jl_jwt).verdict, 'malformed', 'malformed verdict');

    const none = mockRequest({ rawIn: [] });
    await jsonlog.request(none);
    eq(JSON.parse(none.variables.jl_jwt).verdict, 'missing', 'missing verdict');
});

test('expired tokens set the local time check false', async function () {
    const now = Math.floor(Date.now() / 1000);
    const expired = shapedToken({ alg: 'RS256' }, { sub: 'u', exp: now - 120 });
    const r = mockRequest({ rawIn: [['Authorization', 'Bearer ' + expired]] });
    await jsonlog.request(r);
    eq(JSON.parse(r.variables.jl_jwt).jwt.checks.exp_ok, false, 'exp_ok false');
});

test('emit includes auth.jwt with checks and no raw token', async function () {
    const now = Math.floor(Date.now() / 1000);
    const token = shapedToken({ alg: 'RS256', kid: 'k1' }, { sub: 'u', aud: 'api', exp: now + 60 });
    const r = mockRequest({
        rawIn: [['Authorization', 'Bearer ' + token]],
        vars: { time_iso8601: '2026-11-19T20:42:11+00:00', request_id: 'r1', status: '200' },
    });
    await jsonlog.request(r);
    const rec = JSON.parse(jsonlog.emit(r));
    eq(rec.auth.present, true, 'auth.present');
    eq(rec.auth.jwt.checks.exp_ok, true, 'exp_ok');
    eq(rec.auth.jwt.checks.signature_valid, null, 'no verification yet');
    assert(JSON.stringify(rec).indexOf(token) === -1, 'raw token must not appear');
});

test('json request body is captured with secret keys redacted', async function () {
    const body = Buffer.from(JSON.stringify({ items: [1, 2], password: 'hunter2', nested: { client_secret: 's' } }), 'utf8');
    const r = mockRequest({
        method: 'POST',
        rawIn: [['Content-Type', 'application/json'], ['Content-Length', String(body.length)]],
        body: body.buffer.slice(body.byteOffset, body.byteOffset + body.length),
        vars: {},
    });
    await jsonlog.request(r);
    const b = JSON.parse(r.variables.jl_req_body);
    eq(b.state, 'captured', 'state');
    eq(b.encoding, 'utf8', 'encoding');
    eq(b.json.password, '[REDACTED]', 'password redacted');
    eq(b.json.nested.client_secret, '[REDACTED]', 'nested secret redacted');
    eq(b.redaction.mode, 'json_keys', 'mode');
    eq(b.value, null, 'value null when json populated');
});

test('oversize, chunked and kill-switch bodies are not read', async function () {
    const big = mockRequest({ rawIn: [['Content-Length', '40000']], body: new ArrayBuffer(0) });
    await jsonlog.request(big);
    eq(JSON.parse(big.variables.jl_req_body).state, 'omitted_too_large', 'oversize');

    const chunked = mockRequest({ rawIn: [['Transfer-Encoding', 'chunked']] });
    await jsonlog.request(chunked);
    eq(JSON.parse(chunked.variables.jl_req_body).state, 'chunked', 'chunked');

    const off = mockRequest({ rawIn: [['Content-Length', '2']], vars: { jl_bodies: '0' }, body: new ArrayBuffer(2) });
    await jsonlog.request(off);
    eq(JSON.parse(off.variables.jl_req_body).state, 'omitted', 'kill switch');
});

test('binary request body is base64 and never parsed as json', async function () {
    const body = Buffer.from([0x00, 0xff, 0x10, 0x80]);
    const r = mockRequest({
        rawIn: [['Content-Type', 'application/octet-stream'], ['Content-Length', '4']],
        body: body.buffer.slice(body.byteOffset, body.byteOffset + body.length),
    });
    await jsonlog.request(r);
    const b = JSON.parse(r.variables.jl_req_body);
    eq(b.encoding, 'base64', 'encoding');
    eq(b.json, null, 'no json');
    eq(Buffer.from(b.value, 'base64').length, 4, 'round-trips bytes');
});

test('response body accumulates chunks, decodes and redacts', function () {
    const r = mockRequest({
        vars: { status: '200', sent_http_content_type: 'application/json' },
        rawOut: [['Content-Type', 'application/json'], ['Set-Cookie', 'a=1']],
    });
    jsonlog.responseHeaders(r);
    jsonlog.responseBody(r, Buffer.from('{"id":7,'), { last: false });
    jsonlog.responseBody(r, Buffer.from('"password":"x"}'), { last: true });
    const rec = JSON.parse(jsonlog.emit(r));
    eq(rec.response.body.state, 'captured', 'state');
    eq(rec.response.body.json.password, '[REDACTED]', 'redacted');
    eq(rec.response.headers['set-cookie'], '[REDACTED]', 'set-cookie redacted');
    eq(r.out.length, 2, 'every chunk forwarded');
    eq(Buffer.from(r.out[0].d).toString('utf8'), '{"id":7,', 'chunk 1 unchanged');
});

test('response body over cap truncates but forwards every chunk', function () {
    const r = mockRequest({ vars: { status: '200' }, rawOut: [['Content-Type', 'application/octet-stream']] });
    jsonlog.responseHeaders(r);
    const chunk = Buffer.alloc(20000, 0x41);
    jsonlog.responseBody(r, chunk, { last: false });
    jsonlog.responseBody(r, chunk, { last: true });
    const rec = JSON.parse(jsonlog.emit(r));
    eq(rec.response.body.truncated, true, 'truncated');
    eq(rec.response.body.state, 'captured', 'state');
    eq(rec.response.body.encoding, 'base64', 'binary base64');
    assert(rec.response.body.captured_bytes <= 32768, 'cap respected');
    eq(r.out.length, 2, 'both chunks forwarded');
});

test('logging-only: no enforcement surface and unverified tokens are recorded', async function () {
    eq(typeof jsonlog.authRequire, 'undefined', 'no auth handler exported');
    const now = Math.floor(Date.now() / 1000);
    const token = shapedToken({ alg: 'HS256', kid: 'x' }, { sub: 'u', aud: 'account', exp: now + 60 });
    const r = mockRequest({
        rawIn: [['Authorization', 'Bearer ' + token]],
        vars: { status: '200', request_id: 'lo1', time_iso8601: '2026-11-19T20:42:11+00:00' },
    });
    await jsonlog.request(r);
    const rec = JSON.parse(jsonlog.emit(r));
    eq(rec.auth.verdict, 'not_checked', 'decoded but not verified');
    eq(rec.auth.required, false, 'not required');
    eq(rec.auth.jwt.checks.signature_valid, null, 'no signature claim');
    eq(rec.auth.jwt.checks.verified_by, 'none', 'no verifier');
    eq(rec.auth.jwt.header.alg, 'HS256', 'algorithm still logged');
});

test('upstream URL is derived with confidence and never guessed', function () {
    const r = mockRequest({ vars: {
        upstream_addr: '10.0.1.7:8080',
        upstream_last_addr: '10.0.1.7:8080',
        upstream_last_server_name: 'orders_api',
        proxy_host: 'orders_api', proxy_port: '80',
        uri: '/api/v1/orders', args: 'expand=items',
        request_method: 'POST', upstream_status: '200',
        upstream_bytes_sent: '812', upstream_bytes_received: '812',
        upstream_response_length: '812',
    }});
    r.variables.jl_upstream_scheme = 'http';
    const u = jsonlog.__upstream(r);
    eq(u.request.url, 'http://orders_api:80/api/v1/orders?expand=items', 'derived url');
    eq(u.request.url_confidence, 'derived', 'confidence');
    eq(u.peer, '10.0.1.7:8080', 'peer');

    const mapped = mockRequest({ vars: { proxy_host: 'orders_api', proxy_port: '80', uri: '/x', args: '' } });
    mapped.variables.jl_upstream_uri_mapped = '1';
    const u2 = jsonlog.__upstream(mapped);
    eq(u2.request.url, null, 'partial url null');
    eq(u2.request.url_confidence, 'partial', 'partial confidence');
});

test('syslog transport uses 2KiB caps and marks omissions', async function () {
    const body = Buffer.from('x'.repeat(5000));
    const r = mockRequest({
        method: 'POST',
        rawIn: [['Content-Type', 'text/plain'], ['Content-Length', '5000']],
        body: body.buffer.slice(body.byteOffset, body.byteOffset + body.length),
        vars: { jl_transport: 'syslog', status: '200' },
    });
    await jsonlog.request(r);
    const b = JSON.parse(r.variables.jl_req_body);
    eq(b.state, 'omitted_too_large', 'file cap would allow, syslog cap does not');
    const rec = JSON.parse(jsonlog.emit(r));
    eq(rec.log.transport, 'syslog', 'transport');
    eq(rec.log.config.request_cap, 2048, 'cap reported');
});

test('oversize record is trimmed in order and stays parseable', function () {
    const r = mockRequest({ vars: { status: '200', jl_transport: 'syslog' } });
    r.variables.jl_rsp_meta = JSON.stringify({
        status: 200, content_type: 'text/plain', headers: { big: 'y'.repeat(9000) },
        body_state: 'captured', captured_bytes: 0, truncated: false,
    });
    const line = jsonlog.emit(r);
    const rec = JSON.parse(line);
    assert(line.length <= 8192, 'record within budget, got ' + line.length);
    eq(rec.log.truncated, true, 'marked truncated');
    eq(rec.log.truncated_reason, 'transport_limit', 'reason');
    assert(rec.response.status === 200, 'status never dropped');
});

test('malformed query encoding does not collapse the record', function () {
    const r = mockRequest({ vars: {
        time_iso8601: '2026-11-19T20:42:11+00:00', request_id: 'q1',
        args: 'bad=%E0%A4%A&ok=1', uri: '/api/get', request_method: 'GET', status: '200',
    }});
    const rec = JSON.parse(jsonlog.emit(r));
    eq(rec.event, 'http_request', 'still a request record');
    eq(rec.request.args.ok, '1', 'valid arg survives');
    assert(rec.request.args.bad !== undefined, 'malformed arg kept raw');
});

test('response header redactions are recorded with their location', function () {
    const r = mockRequest({ vars: { status: '200' }, rawOut: [['Set-Cookie', 'a=1']] });
    jsonlog.responseHeaders(r);
    const rec = JSON.parse(jsonlog.emit(r));
    eq(rec.response.headers['set-cookie'], '[REDACTED]', 'redacted');
    assert(rec.log.redactions.some(function (x) {
        return x.where === 'response.headers.set-cookie';
    }), 'response redaction recorded');
});

test('syslog budget reserves prefix space and trims large args', function () {
    const r = mockRequest({ vars: {
        status: '200', jl_transport: 'syslog', request_method: 'GET',
        uri: '/api/get', args: 'x=' + 'a'.repeat(9000),
        time_iso8601: '2026-11-19T20:42:11+00:00', request_id: 'big',
    }});
    const line = jsonlog.emit(r);
    const rec = JSON.parse(line);
    assert(line.length <= 7936, 'record plus prefix reserve, got ' + line.length);
    eq(rec.log.truncated, true, 'marked truncated');
    assert(rec.request.method === 'GET', 'core request fields kept');
});

test('bodies without a content type fall back to base64 when not valid utf8', function () {
    const bytes = Buffer.from([0xff, 0x00, 0xfe]);
    const rsp = mockRequest({ vars: { status: '200' }, rawOut: [] });
    jsonlog.responseHeaders(rsp);
    jsonlog.responseBody(rsp, bytes, { last: true });
    eq(JSON.parse(jsonlog.emit(rsp)).response.body.encoding, 'base64', 'response binary');

    const req = mockRequest({
        rawIn: [['Content-Length', '3']],
        body: bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.length),
    });
    return jsonlog.request(req).then(function () {
        eq(JSON.parse(req.variables.jl_req_body).encoding, 'base64', 'request binary');
    });
});

test('an understated content length keeps the declared value and the observed size', async function () {
    const body = Buffer.alloc(100, 0x41);
    const r = mockRequest({
        rawIn: [['Content-Type', 'text/plain'], ['Content-Length', '10']],
        body: body.buffer.slice(body.byteOffset, body.byteOffset + body.length),
    });
    await jsonlog.request(r);
    const b = JSON.parse(r.variables.jl_req_body);
    eq(b.content_length, 10, 'declared value kept');
    eq(b.size, 100, 'observed size');
    eq(b.truncated, false, 'within cap');
});

test('multiple upstream peers are preserved verbatim', function () {
    const r = mockRequest({ vars: {
        upstream_addr: '10.0.0.1:80, 10.0.0.2:80', upstream_status: '200, 200',
        proxy_host: 'orders_api', proxy_port: '80', uri: '/x', args: '',
        request_method: 'GET',
    }});
    eq(jsonlog.__upstream(r).peer, '10.0.0.1:80, 10.0.0.2:80', 'peer list intact');
});

test('token claims are recorded regardless of response status', function () {
    const now = Math.floor(Date.now() / 1000);
    const token = shapedToken({ alg: 'RS256' }, { sub: 'u', exp: now + 60 });
    const r = mockRequest({
        rawIn: [['Authorization', 'Bearer ' + token]],
        vars: { status: '401', request_id: 'a1', time_iso8601: '2026-11-19T20:42:11+00:00' },
    });
    return jsonlog.request(r).then(function () {
        const rec = JSON.parse(jsonlog.emit(r));
        eq(rec.auth.present, true, 'token present');
        eq(rec.auth.verdict, 'not_checked', 'status does not change the logging verdict');
        eq(rec.response.status, 401, 'status recorded');
    });
});

test('a payload that is not json is a malformed token', async function () {
    const notJson = Buffer.from('plain-text').toString('base64').replace(/=+$/, '');
    const r = mockRequest({ rawIn: [['Authorization', 'Bearer a.' + notJson + '.c2ln']] });
    await jsonlog.request(r);
    const a = JSON.parse(r.variables.jl_jwt);
    eq(a.verdict, 'malformed', 'malformed');
    eq(a.error.code, 'decode', 'decode error');
});

test('declared-but-empty variables do not break emit', function () {
    const r = mockRequest({ vars: {
        time_iso8601: '2026-11-19T20:42:11+00:00', request_id: 'e0',
        jl_req_meta: '', jl_errors: '', jl_rsp_meta: '',
    }});
    const rec = JSON.parse(jsonlog.emit(r));
    eq(rec.event, 'http_request', 'still a request record');
    eq(rec.ts, '2026-11-19T20:42:11+00:00', 'ts kept');
});

test('401 with an expired token is decoded at log phase and names the defect', function () {
    const now = Math.floor(Date.now() / 1000);
    const token = shapedToken({ alg: 'RS256' }, { sub: 'u', exp: now - 60 });
    const r = mockRequest({
        rawIn: [['Authorization', 'Bearer ' + token]],
        vars: { status: '401', request_id: 'e1', time_iso8601: '2026-11-19T20:42:11+00:00' },
    });
    const rec = JSON.parse(jsonlog.emit(r));
    eq(rec.auth.present, true, 'decoded at log phase');
    eq(rec.auth.jwt.claims.sub, 'u', 'claims available');
    eq(rec.auth.validation.errors[0].code, 'expired', 'expired');
    eq(rec.auth.validation.reason_hint, null, 'a local defect explains the 401');
});

test('401 with a locally clean token reports only an unverifiable cause', function () {
    const now = Math.floor(Date.now() / 1000);
    const token = shapedToken({ alg: 'RS256' }, { sub: 'u', exp: now + 60 });
    const r = mockRequest({
        rawIn: [['Authorization', 'Bearer ' + token]],
        vars: { status: '401', request_id: 'e2', time_iso8601: '2026-11-19T20:42:11+00:00' },
    });
    const rec = JSON.parse(jsonlog.emit(r));
    eq(rec.auth.validation.errors.length, 0, 'no observable defect');
    eq(rec.auth.validation.reason_hint, 'signature_or_key', 'hypothesis named');
    assert(rec.auth.validation.note !== null, 'limit stated');
});

test('malformed token on 401 is reported as malformed_token', function () {
    const notJson = Buffer.from('plain-text').toString('base64').replace(/=+$/, '');
    const r = mockRequest({
        rawIn: [['Authorization', 'Bearer a.' + notJson + '.c2ln']],
        vars: { status: '401', request_id: 'e3', time_iso8601: '2026-11-19T20:42:11+00:00' },
    });
    const rec = JSON.parse(jsonlog.emit(r));
    eq(rec.auth.validation.errors[0].code, 'malformed_token', 'malformed');
});

test('configured expectations produce iss, aud and alg mismatches', function () {
    const now = Math.floor(Date.now() / 1000);
    const token = shapedToken({ alg: 'HS256' }, { iss: 'https://other', sub: 'u', aud: 'account', exp: now + 60 });
    const r = mockRequest({
        rawIn: [['Authorization', 'Bearer ' + token]],
        vars: {
            status: '401', request_id: 'e4', time_iso8601: '2026-11-19T20:42:11+00:00',
            jl_expected_issuer: 'https://expected', jl_expected_audience: 'api',
            jl_allowed_algs: 'RS256',
        },
    });
    const rec = JSON.parse(jsonlog.emit(r));
    const codes = rec.auth.validation.errors.map(function (e) { return e.code; });
    assert(codes.indexOf('issuer_mismatch') !== -1, 'issuer');
    assert(codes.indexOf('audience_mismatch') !== -1, 'audience');
    assert(codes.indexOf('alg_not_allowed') !== -1, 'algorithm');
});

test('401 with no bearer and a Bearer challenge reports token_missing', function () {
    const r = mockRequest({
        rawIn: [],
        rawOut: [['WWW-Authenticate', 'Bearer realm="api"']],
        vars: { status: '401', request_id: 'e5', time_iso8601: '2026-11-19T20:42:11+00:00' },
    });
    const rec = JSON.parse(jsonlog.emit(r));
    eq(rec.auth.verdict, 'missing', 'missing');
    eq(rec.auth.validation.errors[0].code, 'token_missing', 'named');
});
