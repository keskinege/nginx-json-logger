import crypto from 'crypto';

const SCHEMA_VERSION = '1.0.0';

const V = {
    errors: 'jl_errors',
};

const REDACT_HEADERS = [
    'authorization', 'proxy-authorization', 'cookie', 'set-cookie',
    'x-api-key', 'x-auth-token', 'x-amz-security-token',
];

function safeVar(r, name, fallback) {
    try {
        const v = r.variables[name];
        return (v === undefined || v === null) ? fallback : v;
    } catch (e) { return fallback; }
}

function jsonVar(r, name, fallback) {
    const v = safeVar(r, name, '');
    if (!v) { return fallback; }
    try { return JSON.parse(v); } catch (e) { return fallback; }
}

function setVar(r, name, value) {
    try { r.variables[name] = value; }
    catch (e) { recordError(r, 'var:' + name, e); }
}

function recordError(r, where, err) {
    try {
        const list = jsonVar(r, V.errors, []);
        list.push({ component: where, message: String(err) });
        r.variables[V.errors] = JSON.stringify(list);
    } catch (e) { /* last resort: never throw */ }
    try { r.error(where + ': ' + String(err)); } catch (e) { /* ignore */ }
}

function isRedactedHeader(name) { return REDACT_HEADERS.indexOf(String(name).toLowerCase()) !== -1; }

function readHeaders(rawPairs, where) {
    const headers = {};
    const redactions = [];
    const seen = [];
    const pairs = rawPairs || [];
    for (let pi = 0; pi < pairs.length; pi++) {
        const pair = pairs[pi];
        const name = String(pair[0]).toLowerCase();
        const value = pair[1];
        if (isRedactedHeader(name)) {
            headers[name] = '[REDACTED]';
            const at = where + '.' + name;
            if (seen.indexOf(at) === -1) { seen.push(at); redactions.push({ where: at }); }
            continue;
        }
        if (headers[name] === undefined) { headers[name] = value; }
        else if (Array.isArray(headers[name])) { headers[name].push(value); }
        else { headers[name] = [headers[name], value]; }
    }
    return { headers: headers, redactions: redactions };
}

function safeDecode(s) {
    try { return decodeURIComponent(s); } catch (e) { return s; }
}

function parseArgs(raw) {
    const out = {};
    if (!raw) { return out; }
    const parts = String(raw).split('&');
    for (let pi = 0; pi < parts.length; pi++) {
        const part = parts[pi];
        if (!part) { continue; }
        const i = part.indexOf('=');
        const k = safeDecode(i === -1 ? part : part.slice(0, i));
        const v = i === -1 ? '' : safeDecode(part.slice(i + 1));
        if (out[k] === undefined) { out[k] = v; }
        else if (Array.isArray(out[k])) { out[k].push(v); }
        else { out[k] = [out[k], v]; }
    }
    return out;
}

const CLOCK_SKEW_S = 30;

function b64urlBytes(s) {
    let t = String(s).replace(/-/g, '+').replace(/_/g, '/');
    while (t.length % 4) { t += '='; }
    return Buffer.from(t, 'base64');
}

function b64urlJson(s) {
    try { return JSON.parse(b64urlBytes(s).toString('utf8')); }
    catch (e) { return null; }
}

function sha256Hex(data) {
    const h = crypto.createHash('sha256');
    h.update(data);
    return h.digest('hex');
}

function dedupe(arr) {
    const out = [];
    for (let i = 0; i < arr.length; i++) {
        const x = arr[i];
        if (out.indexOf(x) === -1) { out.push(x); }
    }
    return out;
}

function deriveClaims(claims, now) {
    const scopes = typeof claims.scope === 'string' ? claims.scope.split(/\s+/).filter(Boolean) : [];
    const audiences = Array.isArray(claims.aud) ? claims.aud : (claims.aud ? [claims.aud] : []);
    const roles = [];
    if (claims.realm_access && Array.isArray(claims.realm_access.roles)) {
        for (let i = 0; i < claims.realm_access.roles.length; i++) { roles.push(claims.realm_access.roles[i]); }
    }
    if (claims.resource_access && typeof claims.resource_access === 'object') {
        const raKeys = Object.keys(claims.resource_access);
        for (let ki = 0; ki < raKeys.length; ki++) {
            const ra = claims.resource_access[raKeys[ki]];
            if (ra && Array.isArray(ra.roles)) {
                for (let ri = 0; ri < ra.roles.length; ri++) { roles.push(ra.roles[ri]); }
            }
        }
    }
    return {
        expires_in_s: typeof claims.exp === 'number' ? claims.exp - now : null,
        age_s: typeof claims.iat === 'number' ? now - claims.iat : null,
        scopes: scopes, audiences: audiences, issuer: claims.iss || null,
        roles: dedupe(roles),
        groups: Array.isArray(claims.groups) ? claims.groups : [],
    };
}

function bearer(r) {
    const h = r.headersIn.authorization;
    if (!h) { return { present: false }; }
    const m = /^Bearer\s+(.+)$/i.exec(String(h).trim());
    if (!m) { return { present: true, scheme: String(h).split(/\s+/)[0], token: null }; }
    return { present: true, scheme: 'Bearer', token: m[1] };
}

function readJwt(r) {
    const b = bearer(r);
    if (!b.present) {
        return { present: false, scheme: null, source: null, verdict: 'missing', error: null, jwt: null };
    }
    if (!b.token || String(b.token).split('.').length !== 3) {
        return { present: true, scheme: b.scheme || null, source: 'authorization',
                 verdict: 'malformed', error: { code: 'segments', detail: 'expected three segments' }, jwt: null };
    }
    const parts = String(b.token).split('.');
    const header = b64urlJson(parts[0]);
    const claims = b64urlJson(parts[1]);
    if (!header || !claims) {
        return { present: true, scheme: 'Bearer', source: 'authorization',
                 verdict: 'malformed', error: { code: 'decode', detail: 'header or payload is not JSON' }, jwt: null };
    }
    const now = Math.floor(Date.now() / 1000);
    const expOk = typeof claims.exp === 'number' ? now <= claims.exp + CLOCK_SKEW_S : null;
    const nbfOk = typeof claims.nbf === 'number' ? now + CLOCK_SKEW_S >= claims.nbf : null;
    const iatOk = typeof claims.iat === 'number' ? claims.iat <= now + CLOCK_SKEW_S : null;
    return {
        present: true, scheme: 'Bearer', source: 'authorization',
        verdict: 'not_checked', error: null,
        jwt: {
            fingerprint_sha256: sha256Hex(String(b.token)),
            raw_length: String(b.token).length,
            segments: { header_bytes: parts[0].length, payload_bytes: parts[1].length, signature_bytes: parts[2].length },
            header: { alg: header.alg || null, typ: header.typ || null, kid: header.kid || null,
                      cty: header.cty || null, crit: header.crit || null },
            claims: claims,
            derived: deriveClaims(claims, now),
            checks: { signature_valid: null, alg_ok: null, exp_ok: expOk, nbf_ok: nbfOk, iat_ok: iatOk,
                      iss_ok: null, aud_ok: null, required_claims_ok: null,
                      clock_skew_s: CLOCK_SKEW_S, verified_by: 'none' },
            claims_redacted: [],
        },
    };
}

const TRANSPORT_LIMITS = {
    file:   { req: 32768, rsp: 32768 },
    syslog: { req: 2048,  rsp: 2048  },
};
const SYSLOG_RECORD_BUDGET = 8192;
const SYSLOG_PREFIX_RESERVE = 256;
const TEXT_TYPE_RE = /^text\/|application\/(json|xml|x-www-form-urlencoded|javascript|graphql)/i;
const REDACT_KEY_RE = /^(password|passwd|secret|token|client_secret|api_key|access_token|refresh_token|id_token|card_number|cvv|ssn|pin)$/i;

function isTextBody(ct, buf) {
    if (ct) { return TEXT_TYPE_RE.test(ct); }
    return buf.toString('utf8').indexOf('\uFFFD') === -1;
}

function transport(r) {
    const t = safeVar(r, 'jl_transport', 'file');
    return TRANSPORT_LIMITS[t] ? t : 'file';
}

function limits(r) { return TRANSPORT_LIMITS[transport(r)]; }

function redactValue(obj, hits, depth) {
    if (depth > 20 || obj === null || typeof obj !== 'object') { return obj; }
    if (Array.isArray(obj)) {
        return obj.map(function (v) { return redactValue(v, hits, depth + 1); });
    }
    const out = {};
    const keys = Object.keys(obj);
    for (let ki = 0; ki < keys.length; ki++) {
        const k = keys[ki];
        if (REDACT_KEY_RE.test(k)) { out[k] = '[REDACTED]'; if (hits.indexOf(k) === -1) { hits.push(k); } }
        else { out[k] = redactValue(obj[k], hits, depth + 1); }
    }
    return out;
}

function redactForm(text, hits) {
    return String(text).split('&').map(function (part) {
        const i = part.indexOf('=');
        if (i === -1) { return part; }
        const k = decodeURIComponent(part.slice(0, i));
        if (!REDACT_KEY_RE.test(k)) { return part; }
        if (hits.indexOf(k) === -1) { hits.push(k); }
        return k + '=[REDACTED]';
    }).join('&');
}

function emptyBody(state, contentType, contentLength) {
    return {
        state: state, content_type: contentType, content_length: contentLength,
        size: null, captured_bytes: 0, truncated: false, encoding: 'utf8',
        sha256: null, json: null, value: null, redaction: { mode: 'none', hits: [] },
    };
}

async function captureRequestBody(r) {
    const ct = r.headersIn['content-type'] || null;
    const clRaw = r.headersIn['content-length'];
    const cl = clRaw === undefined ? null : parseInt(clRaw, 10);
    if (safeVar(r, 'jl_bodies', '1') === '0') {
        setVar(r, 'jl_req_body', JSON.stringify(emptyBody('omitted', ct, cl))); return;
    }
    if (cl === null) {
        setVar(r, 'jl_req_body', JSON.stringify(emptyBody('chunked', ct, null))); return;
    }
    const cap = limits(r).req;
    if (!(cl <= cap)) {
        setVar(r, 'jl_req_body', JSON.stringify(emptyBody('omitted_too_large', ct, cl))); return;
    }
    let buf;
    try { buf = Buffer.from(await r.readRequestArrayBuffer()); }
    catch (e) {
        recordError(r, 'request_body', e);
        setVar(r, 'jl_req_body', JSON.stringify(emptyBody('error', ct, cl))); return;
    }
    const meta = emptyBody('captured', ct, cl);
    meta.size = buf.length;
    meta.sha256 = sha256Hex(buf);
    let captured = buf;
    if (captured.length > cap) { captured = captured.slice(0, cap); meta.truncated = true; }
    meta.captured_bytes = captured.length;
    const isText = isTextBody(ct, captured);
    if (isText) {
        meta.encoding = 'utf8';
        meta.value = captured.toString('utf8');
        if (/application\/json/i.test(ct || '') && !meta.truncated) {
            try {
                const parsed = JSON.parse(meta.value);
                const hits = [];
                meta.json = redactValue(parsed, hits, 0);
                meta.redaction = { mode: 'json_keys', hits: hits };
                meta.value = null;
            } catch (e) { meta.redaction = { mode: 'none', hits: [] }; }
        } else if (/x-www-form-urlencoded/i.test(ct || '')) {
            const hits = [];
            meta.value = redactForm(meta.value, hits);
            meta.redaction = { mode: 'form_keys', hits: hits };
        }
    } else {
        meta.encoding = 'base64';
        meta.value = captured.toString('base64');
    }
    setVar(r, 'jl_req_body', JSON.stringify(meta));
}

async function request(r) {
    try {
        const h = readHeaders(r.rawHeadersIn, 'request.headers');
        setVar(r, 'jl_req_meta', JSON.stringify({ headers: h.headers, redactions: h.redactions }));
        setVar(r, 'jl_jwt', JSON.stringify(readJwt(r)));
        await captureRequestBody(r);
    } catch (e) { recordError(r, 'request', e); }
}

function num(r, name) {
    const v = safeVar(r, name, '');
    if (v === '' || v === '-') { return null; }
    const n = parseFloat(v);
    return isNaN(n) ? null : n;
}

function int(r, name) {
    const n = num(r, name);
    return n === null ? null : Math.trunc(n);
}

function str(r, name) { return safeVar(r, name, '') || null; }

function headerFromPairs(rawPairs, name) {
    const lower = String(name).toLowerCase();
    const pairs = rawPairs || [];
    for (let pi = 0; pi < pairs.length; pi++) {
        if (String(pairs[pi][0]).toLowerCase() === lower) { return pairs[pi][1]; }
    }
    return null;
}

function responseHeaders(r) {
    try {
        const h = readHeaders(r.rawHeadersOut, 'response.headers');
        const meta = {
            status: r.status,
            content_type: r.headersOut['Content-Type'] || headerFromPairs(r.rawHeadersOut, 'content-type'),
            content_length: r.headersOut['Content-Length'] || headerFromPairs(r.rawHeadersOut, 'content-length'),
            headers: h.headers,
            redactions: h.redactions,
            body_state: 'not_supported',
            captured_bytes: 0,
            truncated: false,
            chunks: 0,
        };
        setVar(r, 'jl_rsp_meta', JSON.stringify(meta));
    } catch (e) { recordError(r, 'response_headers', e); }
}

function rspMeta(r) {
    return jsonVar(r, 'jl_rsp_meta', null);
}

function responseBody(r, data, flags) {
    try {
        const meta = rspMeta(r);
        if (!meta) { return; }
        const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
        const cap = limits(r).rsp;
        const room = cap - meta.captured_bytes;
        if (meta.body_state === 'not_supported') { meta.body_state = buf.length ? 'captured' : 'empty'; }
        if (buf.length && room > 0) {
            const take = buf.length <= room ? buf : buf.slice(0, room);
            const prev = safeVar(r, 'jl_rsp_body', '');
            r.variables.jl_rsp_body = prev ? prev + '\n' + take.toString('base64') : take.toString('base64');
            meta.captured_bytes += take.length;
            meta.chunks += 1;
            if (take.length < buf.length) { meta.truncated = true; }
        } else if (buf.length) { meta.truncated = true; }
        meta.size = (meta.size || 0) + buf.length;
        setVar(r, 'jl_rsp_meta', JSON.stringify(meta));
    } catch (e) { recordError(r, 'response_body', e); }
    finally {
        try { r.sendBuffer(data, flags); } catch (e) { recordError(r, 'response_body_send', e); }
    }
}

function decodeResponseBody(r, meta) {
    const raw = safeVar(r, 'jl_rsp_body', '');
    const parts = raw ? raw.split('\n').filter(Boolean).map(function (s) { return Buffer.from(s, 'base64'); }) : [];
    const buf = parts.length ? Buffer.concat(parts) : Buffer.alloc(0);
    const ct = meta.content_type;
    const out = emptyBody(meta.body_state || 'not_supported', ct, meta.content_length ? parseInt(meta.content_length, 10) : null);
    const isText = isTextBody(ct, buf);
    out.size = meta.size === undefined ? null : meta.size;
    out.captured_bytes = meta.captured_bytes || 0;
    out.truncated = !!meta.truncated;
    out.sha256 = buf.length ? sha256Hex(buf) : null;
    if (!buf.length) { out.value = null; return out; }
    if (isText) {
        out.encoding = 'utf8';
        out.value = buf.toString('utf8');
        if (/application\/json/i.test(ct || '') && !out.truncated) {
            try {
                const hits = [];
                out.json = redactValue(JSON.parse(out.value), hits, 0);
                out.redaction = { mode: 'json_keys', hits: hits };
                out.value = null;
            } catch (e) { /* leave raw */ }
        }
    } else {
        out.encoding = 'base64';
        out.value = buf.toString('base64');
    }
    return out;
}

function splitHostPort(host, port) {
    const h = String(host || '');
    let hostname = h;
    let portOut = String(port || '');
    if (h.charAt(0) === '[') {
        const end = h.indexOf(']');
        if (end !== -1) {
            hostname = h.slice(0, end + 1);
            if (h.charAt(end + 1) === ':') { portOut = h.slice(end + 2); }
        }
    } else {
        const i = h.lastIndexOf(':');
        if (i !== -1 && h.indexOf(':') === i) { hostname = h.slice(0, i); portOut = h.slice(i + 1); }
    }
    return { host: hostname || null, port: portOut || null };
}

function upstreamSection(r) {
    const hp = splitHostPort(safeVar(r, 'proxy_host', ''), safeVar(r, 'proxy_port', ''));
    const scheme = safeVar(r, 'jl_upstream_scheme', 'http') || 'http';
    const uri = safeVar(r, 'uri', '');
    const args = safeVar(r, 'args', '');
    const path = uri + (args ? '?' + args : '');
    const mapped = safeVar(r, 'jl_upstream_uri_mapped', '0') === '1';
    const override = safeVar(r, 'jl_upstream_url', '');
    let url = null;
    let confidence = 'partial';
    if (override) { url = override; confidence = 'overridden'; }
    else if (!mapped && hp.host) {
        const authority = hp.port ? hp.host + ':' + hp.port : hp.host;
        url = scheme + '://' + authority + path;
        confidence = 'derived';
    }
    return {
        peer: safeVar(r, 'upstream_addr', '') || null,
        last_peer: safeVar(r, 'upstream_last_addr', '') || null,
        server_name: safeVar(r, 'upstream_last_server_name', '') || null,
        configured: { host: hp.host, port: hp.port },
        request: {
            method: str(r, 'request_method'), uri: path, url: url,
            url_confidence: confidence, scheme: scheme,
            host_header: safeVar(r, 'jl_upstream_host_header', '') || safeVar(r, 'proxy_host', '') || null,
        },
        status: safeVar(r, 'upstream_status', '') || null,
        cache_status: safeVar(r, 'upstream_cache_status', '') || null,
        bytes_received: int(r, 'upstream_bytes_received'),
        bytes_sent: int(r, 'upstream_bytes_sent'),
        response_length: int(r, 'upstream_response_length'),
        keepalive: null,
    };
}

function trimRecord(rec, budget) {
    let line = JSON.stringify(rec);
    if (line.length <= budget) { return line; }
    rec.log.truncated = true;
    rec.log.truncated_reason = 'transport_limit';
    if (rec.response && rec.response.body) {
        rec.response.body.value = null; rec.response.body.json = null;
        rec.response.body.state = 'omitted_transport_limit';
        rec.response.body.captured_bytes = 0;
    }
    line = JSON.stringify(rec);
    if (line.length <= budget) { return line; }
    if (rec.request && rec.request.body) {
        rec.request.body.value = null; rec.request.body.json = null;
        rec.request.body.state = 'omitted_transport_limit';
        rec.request.body.captured_bytes = 0;
    }
    line = JSON.stringify(rec);
    if (line.length <= budget) { return line; }
    if (rec.response) { rec.response.headers = {}; }
    line = JSON.stringify(rec);
    if (line.length <= budget) { return line; }
    if (rec.request) { rec.request.headers = {}; rec.request.header_count = 0; }
    line = JSON.stringify(rec);
    if (line.length <= budget) { return line; }
    if (rec.request) { rec.request.args = {}; rec.request.raw_args = null; }
    line = JSON.stringify(rec);
    if (line.length <= budget) { return line; }
    if (rec.auth && rec.auth.jwt) { rec.auth.jwt.claims = { claims_redacted: [] }; }
    line = JSON.stringify(rec);
    if (line.length <= budget) { return line; }
    rec.upstream = null;
    line = JSON.stringify(rec);
    if (line.length <= budget) { return line; }
    return JSON.stringify({
        ts: rec.ts, schema_version: rec.schema_version, event: rec.event,
        request_id: rec.request_id, log: rec.log,
    });
}

function csvList(raw) {
    const out = [];
    const parts = String(raw || '').split(',');
    for (let pi = 0; pi < parts.length; pi++) {
        const t = parts[pi].trim();
        if (t) { out.push(t); }
    }
    return out;
}

function audienceHas(claims, expected) {
    const aud = claims ? claims.aud : null;
    if (Array.isArray(aud)) { return aud.indexOf(expected) !== -1; }
    if (typeof aud === 'string') {
        return aud === expected || aud.split(/\s+/).indexOf(expected) !== -1;
    }
    return false;
}

function observe(r, auth) {
    const errors = [];
    if (!auth.present) {
        errors.push({ code: 'token_missing' });
    } else if (!auth.jwt) {
        errors.push({ code: 'malformed_token', detail: auth.error ? auth.error.code : 'decode' });
    } else {
        const c = auth.jwt.claims || {};
        const h = auth.jwt.header || {};
        const now = Math.floor(Date.now() / 1000);
        if (typeof c.exp === 'number' && now > c.exp + CLOCK_SKEW_S) {
            errors.push({ code: 'expired', claim: 'exp', actual: c.exp });
        }
        if (typeof c.nbf === 'number' && now + CLOCK_SKEW_S < c.nbf) {
            errors.push({ code: 'not_yet_valid', claim: 'nbf', actual: c.nbf });
        }
        if (typeof c.iat === 'number' && c.iat > now + CLOCK_SKEW_S) {
            errors.push({ code: 'iat_in_future', claim: 'iat', actual: c.iat });
        }
        const algs = csvList(safeVar(r, 'jl_allowed_algs', ''));
        if (algs.length && h.alg && algs.indexOf(h.alg) === -1) {
            errors.push({ code: 'alg_not_allowed', claim: 'alg', expected: algs, actual: h.alg });
        }
        const issuer = safeVar(r, 'jl_expected_issuer', '');
        if (issuer && c.iss !== issuer) {
            errors.push({ code: 'issuer_mismatch', claim: 'iss', expected: issuer, actual: c.iss || null });
        }
        const audience = safeVar(r, 'jl_expected_audience', '');
        if (audience && !audienceHas(c, audience)) {
            errors.push({ code: 'audience_mismatch', claim: 'aud', expected: audience, actual: c.aud || null });
        }
        if (!c.sub) { errors.push({ code: 'no_subject', claim: 'sub' }); }
    }
    const rejected = int(r, 'status') === 401 || int(r, 'status') === 403;
    return {
        mode: 'observed',
        ok: errors.length === 0,
        signature: 'unverified',
        errors: errors,
        reason_hint: (rejected && auth.present && errors.length === 0) ? 'signature_or_key' : null,
        note: (rejected && errors.length === 0)
            ? '401/403 with no locally observable defect; signature, key selection or an unstated policy caused it'
            : null,
    };
}

function buildAuth(r) {
    const stored = safeVar(r, 'jl_jwt', '');
    if (stored) {
        try { return JSON.parse(stored); }
        catch (e) { recordError(r, 'auth_parse', e); }
    }
    try {
        if (r.headersIn && r.headersIn.authorization) { return readJwt(r); }
    } catch (e) { recordError(r, 'auth_decode', e); }
    if (int(r, 'status') === 401) {
        const challenge = headerFromPairs(r.rawHeadersOut, 'www-authenticate') || '';
        if (/bearer/i.test(String(challenge))) {
            return { present: false, scheme: null, source: null, verdict: 'missing', error: null, jwt: null };
        }
    }
    return null;
}

function emit(r) {
    try {
        const meta = jsonVar(r, 'jl_req_meta', {});
        const rec = {
            ts: str(r, 'time_iso8601'),
            schema_version: SCHEMA_VERSION,
            event: 'http_request',
            request_id: str(r, 'request_id'),
            trace: { traceparent: null, tracestate: null, trace_id: null, span_id: null, sampled: null },
            nginx: {
                pid: int(r, 'pid'),
                connection: int(r, 'connection'),
                connection_requests: int(r, 'connection_requests'),
                msec: num(r, 'msec'),
            },
            client: {
                remote_addr: str(r, 'remote_addr'),
                remote_port: int(r, 'remote_port'),
                realip: str(r, 'realip_remote_addr'),
                x_forwarded_for: safeVar(r, 'http_x_forwarded_for', '') || null,
                user_agent: safeVar(r, 'http_user_agent', '') || null,
                referer: safeVar(r, 'http_referer', '') || null,
            },
            tls: {
                protocol: str(r, 'ssl_protocol'),
                cipher: str(r, 'ssl_cipher'),
                sni: str(r, 'ssl_server_name'),
                client_verify: str(r, 'ssl_client_verify'),
                client_dn: str(r, 'ssl_client_s_dn'),
                client_fingerprint: str(r, 'ssl_client_fingerprint'),
                session_reused: safeVar(r, 'ssl_session_reused', '') === 'r',
                cert: { subject: null, issuer: null, serial: str(r, 'ssl_client_serial'),
                        not_before: str(r, 'ssl_client_v_start'),
                        not_after: str(r, 'ssl_client_v_end'),
                        days_remaining: int(r, 'ssl_client_v_remain') },
            },
            server: {
                name: str(r, 'server_name'), addr: str(r, 'server_addr'),
                port: int(r, 'server_port'), scheme: str(r, 'scheme'),
                host: str(r, 'host'),
            },
            request: {
                method: str(r, 'request_method'), uri: str(r, 'request_uri'),
                path: str(r, 'uri'), protocol: str(r, 'server_protocol'),
                line: str(r, 'request'), length: int(r, 'request_length'),
                host: str(r, 'host'), args: parseArgs(safeVar(r, 'args', '')),
                raw_args: safeVar(r, 'args', '') || null,
                headers: meta.headers || {},
                header_count: Object.keys(meta.headers || {}).length,
                body: safeVar(r, 'jl_req_body', '') ? JSON.parse(safeVar(r, 'jl_req_body', '{}')) : null,
            },
            auth: buildAuth(r),
            response: (function () {
                const m = rspMeta(r);
                return {
                    status: int(r, 'status'), status_text: null,
                    bytes_sent: int(r, 'bytes_sent'), body_bytes_sent: int(r, 'body_bytes_sent'),
                    content_type: str(r, 'sent_http_content_type'),
                    content_encoding: str(r, 'sent_http_content_encoding'),
                    headers: m ? (m.headers || {}) : {},
                    body: m ? decodeResponseBody(r, m) : null,
                };
            })(),
            upstream: safeVar(r, 'upstream_addr', '') ? upstreamSection(r) : null,
            timings: {
                request_s: num(r, 'request_time'),
                upstream_connect_s: num(r, 'upstream_connect_time'),
                upstream_header_s: num(r, 'upstream_header_time'),
                upstream_response_s: num(r, 'upstream_response_time'),
                tcpinfo_rtt_us: int(r, 'tcpinfo_rtt'),
                tcpinfo_rttvar_us: int(r, 'tcpinfo_rttvar'),
            },
            log: {
                truncated: false, truncated_reason: null,
                transport: safeVar(r, 'jl_transport', 'file') || 'file',
                redactions: (meta.redactions || []).concat((rspMeta(r) || {}).redactions || []),
                errors: jsonVar(r, 'jl_errors', []),
                config: { bodies: true, transport: safeVar(r, 'jl_transport', 'file') || 'file',
                          request_cap: limits(r).req, response_cap: limits(r).rsp },
            },
        };
        (function () {
            if (!rec.auth) { return; }
            rec.auth.required = false;
            if (!rec.auth.jwt) { return; }
            const checks = rec.auth.jwt.checks;
            if (!rec.auth.present) { rec.auth.verdict = 'missing'; }
            else if (rec.auth.verdict !== 'malformed') { rec.auth.verdict = 'not_checked'; }
            checks.signature_valid = null;
            checks.alg_ok = null; checks.iss_ok = null;
            checks.aud_ok = null; checks.required_claims_ok = null;
            checks.verified_by = 'none';
        })();
        if (rec.auth) { rec.auth.validation = observe(r, rec.auth); }
        const budget = transport(r) === 'syslog'
            ? SYSLOG_RECORD_BUDGET - SYSLOG_PREFIX_RESERVE
            : Infinity;
        return trimRecord(rec, budget);
    } catch (e) {
        try { r.error('emit_failed: ' + String(e)); } catch (x) { /* ignore */ }
        return '{"ts":null,"schema_version":"1.0.0","event":"log_error","error":{"code":"emit_failed"}}';
    }
}

export default { request, responseHeaders, responseBody, emit, __upstream: upstreamSection };
