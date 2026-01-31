addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request));
});

const SECRET_KEY = "A53xR14L390"; // move to env var in prod

async function handleRequest(req) {
  const urlObj = new URL(req.url);
  const pathSegments = urlObj.pathname.split("/").filter(Boolean);

  // ===== CORS PREFLIGHT =====
  if (req.method === "OPTIONS") {
    return new Response(null, {
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH",
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Max-Age": "86400",
      }
    });
  }

  // ===== AUTH =====
  if (pathSegments.length < 1 || pathSegments[0] !== SECRET_KEY) {
    return jsonError("Unauthorized", 401);
  }

  // ===== TARGET URL =====
  let target;

  if (urlObj.searchParams.has("url")) {
    target = urlObj.searchParams.get("url");
  } else if (pathSegments.length > 1) {
    const keyLength = `/${SECRET_KEY}/`.length;
    target = urlObj.pathname.substring(keyLength) + urlObj.search;
  }

  if (!target) {
    return jsonError("Missing target URL", 400);
  }

  if (!/^https?:\/\//i.test(target)) {
    target = "https://" + target;
  }

  let targetUrl;
  try {
    targetUrl = new URL(target);
  } catch {
    return jsonError("Invalid target URL", 400);
  }

  // ===== BLOCK PRIVATE / LOCAL =====
  const hostname = targetUrl.hostname;
  if (
    hostname === "localhost" ||
    hostname.startsWith("127.") ||
    hostname.startsWith("10.") ||
    hostname.startsWith("192.168.") ||
    hostname.startsWith("172.16.") ||
    hostname === "0.0.0.0" ||
    hostname === "[::]"
  ) {
    return jsonError("Private targets blocked", 403);
  }

  // ===== HEADERS =====
  const headers = new Headers();

  // Copy safe headers only
  for (const [key, value] of req.headers.entries()) {
    if (
      ![
        "host",
        "origin",
        "referer",
        "x-forwarded-for",
        "x-real-ip",
        "cf-connecting-ip",
        "cf-ray",
        "cf-visitor",
        "cf-ipcountry"
      ].includes(key.toLowerCase())
    ) {
      headers.set(key, value);
    }
  }

  // ✅ Forward Cloudflare-verified client IP ONLY
  const clientIP = req.headers.get("cf-connecting-ip");
  if (clientIP) {
    headers.set("cf-connecting-ip", clientIP);
    headers.set("x-forwarded-for", clientIP);
  }

  // Browser-like defaults
  headers.set(
    "user-agent",
    headers.get("user-agent") ||
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
  );
  headers.set(
    "accept",
    headers.get("accept") ||
      "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
  );

  // ===== BODY =====
  let body = null;
  if (!["GET", "HEAD"].includes(req.method)) {
    body = await req.arrayBuffer();
  }

  // ===== FETCH =====
  let res;
  try {
    res = await fetch(targetUrl.toString(), {
      method: req.method,
      headers,
      body,
      redirect: "follow",
      signal: AbortSignal.timeout(30000)
    });
  } catch (err) {
    return jsonError(`Fetch failed: ${err.message}`, 502);
  }

  // ===== RESPONSE =====
  const resHeaders = new Headers(res.headers);
  resHeaders.set("Access-Control-Allow-Origin", "*");
  resHeaders.set("Access-Control-Allow-Headers", "*");
  resHeaders.set("Access-Control-Expose-Headers", "*");
  resHeaders.set("X-Proxied-By", "Cloudflare-Worker");

  // Remove headers that break browsers
  resHeaders.delete("content-security-policy");
  resHeaders.delete("x-frame-options");
  resHeaders.delete("x-content-type-options");

  return new Response(await res.arrayBuffer(), {
    status: res.status,
    headers: resHeaders
  });
}

function jsonError(message, status) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*"
    }
  });
}
