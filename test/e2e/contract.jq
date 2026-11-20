(has("ts") and has("schema_version") and has("event") and has("request_id")) and
(.request | has("method") and has("headers") and has("body")) and
(.response | has("status") and has("headers") and has("body")) and
(.log | has("truncated") and has("transport") and has("errors")) and
((.request.body == null) or (.request.body | has("state") and has("encoding"))) and
((.response.body == null) or (.response.body | has("state") and has("encoding")))
