import jsonlog from '../../njs/jsonlog.js';
import { mockRequest } from './mock.js';

const body = Buffer.from(JSON.stringify({ items: [1, 2], password: 'hunter2' }), 'utf8');
const r = mockRequest({
    method: 'POST',
    uri: '/api/v1/orders',
    args: 'expand=items',
    rawIn: [
        ['Host', 'api.example.com'],
        ['Content-Type', 'application/json'],
        ['Content-Length', String(body.length)],
        ['Authorization', 'Bearer abc.def.ghi'],
        ['Via', '1.1 alpha'],
        ['Via', '1.1 beta'],
    ],
    rawOut: [['Content-Type', 'application/json'], ['Set-Cookie', 'a=1']],
    body: body.buffer.slice(body.byteOffset, body.byteOffset + body.length),
    vars: {
        time_iso8601: '2026-11-19T20:42:11+00:00', request_id: 'sample-1',
        request_method: 'POST', request_uri: '/api/v1/orders?expand=items', uri: '/api/v1/orders',
        args: 'expand=items', server_protocol: 'HTTP/1.1', request: 'POST /api/v1/orders?expand=items HTTP/1.1',
        request_length: '812', host: 'api.example.com', server_name: 'api.example.com',
        server_addr: '10.0.0.10', server_port: '443', scheme: 'https',
        remote_addr: '10.0.0.5', remote_port: '51234', connection: '9',
        connection_requests: '3', msec: '1763584931.221', pid: '42',
        request_time: '0.041', bytes_sent: '1043', body_bytes_sent: '812',
        status: '200', sent_http_content_type: 'application/json',
        upstream_addr: '10.0.1.7:8080', upstream_status: '200',
        upstream_bytes_sent: '812', upstream_bytes_received: '812',
        upstream_response_length: '812', proxy_host: 'orders_api', proxy_port: '80',
    },
});

await jsonlog.request(r);
jsonlog.responseHeaders(r);
jsonlog.responseBody(r, Buffer.from('{"id":7,"status":"created"}'), { last: true });
r.variables.status = '200';
console.log(jsonlog.emit(r));
