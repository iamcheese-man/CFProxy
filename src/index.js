addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request));
});

const SECRET_KEY = "A53xR14L390"; // use an env var in production

async function handleRequest(req) {
  const urlObj = new URL(req.url);
  const pathSegments = urlObj.pathname.split("/").filter(Boolean);

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

  // ✅ Forward Cloudflare-verified client IP
  const clientIP = req.headers.get("cf-connecting-ip");
  if (clientIP) {
    headers.set("cf-connecting-ip", clientIP);
    headers.set("x-forwarded-for", clientIP);
  }

  // ✅ Force the correct Host header (avoids Cloudflare 1003)
  headers.set("host", targetUrl.host);

  // Default browser headers if missing
  headers.set(
    "user-agent",
    headers.get("user-agent") ||
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
  );
  headers.set(
    "accept",
    headers.get("accept") || "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
  );

  // ===== Handle body =====
  let body = null;
  if (!["GET", "HEAD"].includes(req.method)) {
    body = await req.arrayBuffer();
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

  // Remove headers that might break browser rendering
  resHeaders.delete("content-security-policy");
  resHeaders.delete("x-frame-options");
  resHeaders.delete("x-content-type-options");

  return new Response(await res.arrayBuffer(), {
    status: res.status,
    statusText: res.statusText,
    headers: resHeaders,
  });
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
