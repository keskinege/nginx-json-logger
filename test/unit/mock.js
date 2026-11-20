function lowerPairs(pairs) {
    const out = {};
    const list = pairs || [];
    for (let pi = 0; pi < list.length; pi++) {
        const p = list[pi];
        const k = String(p[0]).toLowerCase();
        if (out[k] === undefined) { out[k] = p[1]; }
        else if (Array.isArray(out[k])) { out[k].push(p[1]); }
        else { out[k] = [out[k], p[1]]; }
    }
    return out;
}

export function mockRequest(spec) {
    const s = spec || {};
    const rawIn = s.rawIn || [];
    const rawOut = s.rawOut || [];
    const out = [];
    const r = {
        variables: {},
        method: s.method || 'GET',
        uri: s.uri || '/',
        args: s.args || '',
        status: s.status || 200,
        headersIn: lowerPairs(rawIn),
        rawHeadersIn: rawIn,
        headersOut: {},
        rawHeadersOut: rawOut,
        out: out,
        sendBuffer: function (d, f) { out.push({ d: d, f: f }); },
        error: function (m) { (this.errors = this.errors || []).push(String(m)); },
        readRequestArrayBuffer: async function () {
            return s.body === undefined ? new ArrayBuffer(0) : s.body;
        },
    };
    const base = s.vars || {};
    const baseKeys = Object.keys(base);
    for (let ki = 0; ki < baseKeys.length; ki++) { r.variables[baseKeys[ki]] = base[baseKeys[ki]]; }
    return r;
}

export function assert(cond, msg) {
    if (!cond) { throw new Error(msg); }
}

export function eq(actual, expected, msg) {
    const a = JSON.stringify(actual);
    const e = JSON.stringify(expected);
    if (a !== e) { throw new Error(msg + ': expected ' + e + ', got ' + a); }
}

export async function runTests(tests) {
    const results = [];
    for (let ti = 0; ti < tests.length; ti++) {
        const t = tests[ti];
        try { await t.fn(); results.push({ name: t.name, ok: true }); }
        catch (e) { results.push({ name: t.name, ok: false, error: String(e) }); }
    }
    const failures = results.filter(function (x) { return !x.ok; });
    return { passed: results.length - failures.length, failed: failures.length, failures: failures };
}
