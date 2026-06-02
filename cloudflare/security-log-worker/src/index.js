const jsonHeaders = {
  "Content-Type": "application/json; charset=utf-8",
};

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: jsonHeaders,
  });
}

function trimText(value) {
  return typeof value === "string" ? value.trim() : "";
}

function readAuthToken(request, headerName) {
  const direct = trimText(request.headers.get(headerName));
  if (direct) return direct;

  const authorization = trimText(request.headers.get("Authorization"));
  const prefix = "Bearer ";
  if (authorization.startsWith(prefix)) {
    return authorization.slice(prefix.length).trim();
  }
  return "";
}

function verifyToken(request, expectedToken, headerName) {
  const expected = trimText(expectedToken);
  if (!expected) return false;
  return readAuthToken(request, headerName) === expected;
}

function requestId(request) {
  const ray = trimText(request.headers.get("CF-Ray"));
  if (ray) return ray;
  const cryptoValue = crypto.randomUUID ? crypto.randomUUID() : String(Date.now());
  return `worker-${cryptoValue}`;
}

async function sha256Hex(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function sanitizePath(pathname) {
  return pathname || "/";
}

function serializeRaw(raw) {
  try {
    return JSON.stringify(raw ?? {});
  } catch {
    return "{}";
  }
}

async function parseCollectPayload(request) {
  const url = new URL(request.url);
  const body = request.headers.get("Content-Type")?.includes("application/json") ? await request.json().catch(() => ({})) : {};
  const cf = request.cf || {};
  const clientIp = trimText(body.clientIp) || trimText(request.headers.get("CF-Connecting-IP"));
  const occurredAt = trimText(body.occurredAt) || new Date().toISOString();
  const pathValue = trimText(body.path) || sanitizePath(trimText(body.pathname) || url.pathname);
  const query = trimText(body.query) || trimText(body.search) || url.search.replace(/^\?/, "");
  const request_id = trimText(body.requestId) || requestId(request);

  return {
    id: trimText(body.id) || request_id,
    received_at: new Date().toISOString(),
    occurred_at: occurredAt,
    client_ip: clientIp,
    ip_hash: clientIp ? await sha256Hex(clientIp) : "",
    country: trimText(body.country) || trimText(cf.country),
    region: trimText(body.region) || trimText(cf.region),
    city: trimText(body.city) || trimText(cf.city),
    colo: trimText(body.colo) || trimText(cf.colo),
    method: (trimText(body.method) || request.method || "GET").toUpperCase(),
    host: trimText(body.host) || trimText(request.headers.get("Host")),
    path: pathValue,
    query,
    status_code: Number(body.statusCode || body.status_code || 0) || 0,
    user_agent: trimText(body.userAgent) || trimText(request.headers.get("User-Agent")),
    referer: trimText(body.referer) || trimText(request.headers.get("Referer")),
    cf_ray: trimText(body.cfRay) || trimText(request.headers.get("CF-Ray")),
    request_id,
    response_bytes: Number(body.responseBytes || body.response_bytes || 0) || 0,
    source: trimText(body.source) || "worker",
    raw_json: serializeRaw({
      body,
      cf: {
        country: cf.country,
        region: cf.region,
        city: cf.city,
        colo: cf.colo,
        asn: cf.asn,
        clientTcpRtt: cf.clientTcpRtt,
      },
    }),
  };
}

async function collect(request, env) {
  if (!verifyToken(request, env.INGEST_TOKEN, "X-Security-Ingest-Token")) {
    return jsonResponse({ success: false, message: "INGEST_TOKEN is missing or invalid." }, 401);
  }

  const row = await parseCollectPayload(request);
  await env.SECURITY_LOG_DB.prepare(
    `
    INSERT INTO access_logs (
      id, received_at, occurred_at, client_ip, ip_hash, country, region, city, colo,
      method, host, path, query, status_code, user_agent, referer, cf_ray,
      request_id, response_bytes, source, raw_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      received_at = excluded.received_at,
      status_code = excluded.status_code,
      response_bytes = excluded.response_bytes,
      raw_json = excluded.raw_json
    `
  )
    .bind(
      row.id,
      row.received_at,
      row.occurred_at,
      row.client_ip,
      row.ip_hash,
      row.country,
      row.region,
      row.city,
      row.colo,
      row.method,
      row.host,
      row.path,
      row.query,
      row.status_code,
      row.user_agent,
      row.referer,
      row.cf_ray,
      row.request_id,
      row.response_bytes,
      row.source,
      row.raw_json
    )
    .run();

  return jsonResponse({ success: true, data: { id: row.id, receivedAt: row.received_at } });
}

async function exportRows(request, env) {
  if (!verifyToken(request, env.EXPORT_TOKEN, "X-Security-Export-Token")) {
    return jsonResponse({ success: false, message: "EXPORT_TOKEN is missing or invalid." }, 401);
  }

  const url = new URL(request.url);
  const cursor = Math.max(0, Number(url.searchParams.get("cursor") || 0) || 0);
  const limit = Math.max(1, Math.min(Number(url.searchParams.get("limit") || 500) || 500, 1000));
  const result = await env.SECURITY_LOG_DB.prepare(
    `
    SELECT
      rowid AS cursor, id, received_at, occurred_at, client_ip, ip_hash,
      country, region, city, colo, method, host, path, query, status_code,
      user_agent, referer, cf_ray, request_id, response_bytes, source, raw_json
    FROM access_logs
    WHERE rowid > ?
    ORDER BY rowid ASC
    LIMIT ?
    `
  )
    .bind(cursor, limit)
    .all();

  const rows = result.results || [];
  const nextCursor = rows.length ? Number(rows[rows.length - 1].cursor) : cursor;
  return jsonResponse({
    success: true,
    data: {
      rows,
      cursor,
      nextCursor,
      hasMore: rows.length === limit,
    },
  });
}

async function health(env) {
  const result = await env.SECURITY_LOG_DB.prepare("SELECT COUNT(*) AS count FROM access_logs").first();
  return jsonResponse({
    success: true,
    data: {
      status: "online",
      rows: Number(result?.count || 0),
      time: new Date().toISOString(),
    },
  });
}

const worker = {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname === "/collect") return collect(request, env);
    if (request.method === "GET" && url.pathname === "/export") return exportRows(request, env);
    if (request.method === "GET" && url.pathname === "/health") return health(env);
    return jsonResponse({ success: false, message: "Not found." }, 404);
  },
};

export default worker;
