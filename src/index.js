addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request, event));
});

const SECRET_KEY = "A53xR14L390"; // use an environment variable in production
const RATE_LIMIT = 61;
const RATE_WINDOW = 60 * 1000; // 60 seconds

async function handleRequest(req, event) {
  // ===== Rate limiting =====
  const clientIP = req.headers.get("cf-connecting-ip") || "unknown";
  const cacheKey = `ratelimit:${clientIP}`;
  const now = Date.now();
  const cache = caches.default;

  const data = await cache.match(cacheKey);
  let state = data ? await data.json() : { count: 0, start: now };

  if (now - state.start > RATE_WINDOW) {
    state.count = 1;
    state.start = now;
  } else {
    state.count++;
  }

  if (state.count > RATE_LIMIT) {
    return jsonError("Rate limit exceeded (61 requests per minute)", 429);
  }

  const resp = new Response(JSON.stringify(state), { status: 200 });
  event.waitUntil(cache.put(cacheKey, resp, { expirationTtl: 60 }));

  // ===== CORS preflight =====
  if (req.method === "OPTIONS") {
    return new Response(null, {
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH",
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Max-Age": "86400",
      },
    });
  }

  // ===== Secret key check =====
  const urlObj = new URL(req.url);
  const pathSegments = urlObj.pathname.split("/").filter(Boolean);

  if (pathSegments.length < 1 || pathSegments[0] !== SECRET_KEY) {
    return jsonError("Unauthorized: invalid or missing key", 401);
  }

  // ===== Determine target URL =====
  let target;
  if (urlObj.searchParams.has("url")) {
    target = urlObj.searchParams.get("url");
  } else if (pathSegments.length > 1) {
    const keyLength = `/${SECRET_KEY}/`.length;
    target = urlObj.pathname.substring(keyLength) + urlObj.search;
  }

  if (!target) return jsonError("Missing target URL", 400);

  if (!/^https?:\/\//i.test(target)) target = "https://" + target;

  let targetUrl;
  try {
    targetUrl = new URL(target);
  } catch {
    return jsonError("Invalid target URL", 400);
  }

  // ===== Block private / local IPs =====
  const host = targetUrl.hostname;
  if (
    host === "localhost" ||
    host.startsWith("127.") ||
    host.startsWith("10.") ||
    host.startsWith("192.168.") ||
    host.startsWith("172.16.") ||
    host === "0.0.0.0" ||
    host === "[::]"
  ) {
    return jsonError("Private/local addresses are blocked", 403);
  }

  // ===== Build headers =====
  const headers = new Headers();
  for (const [key, value] of req.headers.entries()) {
    if (![
      "host",
      "origin",
      "referer",
      "x-forwarded-for",
      "x-real-ip",
      "cf-connecting-ip",
      "cf-ray",
      "cf-visitor",
      "cf-ipcountry"
    ].includes(key.toLowerCase())) {
      headers.set(key, value);
    }
  }

  if (clientIP) {
    headers.set("cf-connecting-ip", clientIP);
    headers.set("x-forwarded-for", clientIP);
  }

  headers.set("host", targetUrl.host);
  headers.set(
    "user-agent",
    headers.get("user-agent") ||
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
  );
  headers.set(
    "accept",
    headers.get("accept") || "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
  );

  // ===== Handle request body =====
  let body = null;
  if (!["GET", "HEAD"].includes(req.method)) {
    body = await req.arrayBuffer();
  }

  // ===== Cache lookup for GET requests =====
  if (req.method === "GET") {
    const cachedResponse = await cache.match(req);
    if (cachedResponse) return cachedResponse;
  }

  // ===== Fetch target =====
  let res;
  try {
    res = await fetch(targetUrl.toString(), {
      method: req.method,
      headers,
      body,
      redirect: "follow",
      signal: AbortSignal.timeout(30000),
    });
  } catch (err) {
    return jsonError(`Fetch failed: ${err.message}`, 502);
  }

  // ===== Forward response =====
  const resHeaders = new Headers(res.headers);
  resHeaders.set("Access-Control-Allow-Origin", "*");
  resHeaders.set("Access-Control-Allow-Headers", "*");
  resHeaders.set("Access-Control-Expose-Headers", "*");
  resHeaders.set("X-Proxied-By", "Cloudflare Worker");

  // Remove headers that may break browser rendering
  resHeaders.delete("content-security-policy");
  resHeaders.delete("x-frame-options");
  resHeaders.delete("x-content-type-options");

  const finalResponse = new Response(res.body, {
    status: res.status,
    statusText: res.statusText,
    headers: resHeaders,
  });

  // ===== Cache successful GET responses =====
  if (req.method === "GET" && res.status >= 200 && res.status < 300) {
    event.waitUntil(cache.put(req, finalResponse.clone()));
  }

  return finalResponse;
}

// ===== Helper: JSON error =====
function jsonError(message, status = 400) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    },
  });
}
