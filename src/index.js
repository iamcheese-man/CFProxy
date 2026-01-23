addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request));
});

const SECRET_KEY = "A53xR14L390"; // change this to your secret key

async function handleRequest(req) {
  const urlObj = new URL(req.url);
  const pathSegments = urlObj.pathname.split("/").filter(Boolean);
  
  // Handle OPTIONS preflight for CORS
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
  
  // ==== ENFORCE KEY ====
  if (pathSegments.length < 1) {
    return jsonError("Unauthorized: key missing", 401);
  }
  
  if (pathSegments[0] !== SECRET_KEY) {
    return jsonError("Unauthorized: invalid key", 401);
  }
  
  // ==== DETERMINE TARGET URL ====
  let target = null;
  
  // Query parameter style: /KEY?url=https://example.com
  if (urlObj.searchParams.has("url")) {
    target = urlObj.searchParams.get("url");
  }
  // Path style: /KEY/https://example.com/path
  else if (pathSegments.length > 1) {
    const keyLength = `/${SECRET_KEY}/`.length;
    const pathAfterKey = urlObj.pathname.substring(keyLength);
    target = pathAfterKey;
    
    // Preserve query parameters from original request
    if (urlObj.search && !target.includes("?")) {
      target += urlObj.search;
    }
  }
  
  if (!target) {
    return jsonError("Missing target URL. Usage: /{key}/{url} or /{key}?url={url}", 400);
  }
  
  // Auto-add https:// if missing
  if (!/^https?:\/\//i.test(target)) {
    target = "https://" + target;
  }
  
  // Validate target URL
  let targetUrl;
  try {
    targetUrl = new URL(target);
  } catch (err) {
    return jsonError(`Invalid target URL: ${err.message}`, 400);
  }
  
  // Security: Block access to private/local IPs
  const hostname = targetUrl.hostname;
  if (
    hostname === "localhost" ||
    hostname.startsWith("127.") ||
    hostname.startsWith("192.168.") ||
    hostname.startsWith("10.") ||
    hostname.startsWith("172.16.") ||
    hostname === "0.0.0.0" ||
    hostname === "[::]"
  ) {
    return jsonError("Access to private/local addresses is not allowed", 403);
  }
  
  // Clone headers and remove problematic ones
  const headers = new Headers(req.headers);
  const headersToRemove = [
    "host", "origin", "referer",
    "cf-connecting-ip", "cf-ray", "cf-visitor", "cf-ipcountry",
    "x-forwarded-for", "x-forwarded-proto", "x-real-ip"
  ];
  headersToRemove.forEach(h => headers.delete(h));
  
  // Browser-like defaults
  if (!headers.has("user-agent")) {
    headers.set("user-agent", 
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    );
  }
  if (!headers.has("accept")) {
    headers.set("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
  }
  if (!headers.has("accept-language")) {
    headers.set("accept-language", "en-US,en;q=0.9");
  }
  if (!headers.has("accept-encoding")) {
    headers.set("accept-encoding", "gzip, deflate, br");
  }
  
  // Handle request body for non-GET/HEAD requests
  let body = null;
  if (!["GET", "HEAD"].includes(req.method)) {
    const contentType = req.headers.get("content-type");
    if (contentType && contentType.includes("application/json")) {
      body = await req.text();
    } else if (contentType && contentType.includes("multipart/form-data")) {
      body = await req.arrayBuffer();
    } else {
      body = await req.text();
    }
  }
  
  let res;
  try {
    res = await fetch(targetUrl.toString(), {
      method: req.method,
      headers,
      body,
      redirect: "follow",
      // Add timeout protection (Cloudflare Workers have 50s CPU time limit)
      signal: AbortSignal.timeout(30000) // 30 second timeout
    });
  } catch (err) {
    if (err.name === "TimeoutError") {
      return jsonError("Request timeout: target server took too long to respond", 504);
    }
    return jsonError(`Fetch failed: ${err.message}`, 502);
  }
  
  // Forward headers + CORS
  const resHeaders = new Headers(res.headers);
  resHeaders.set("Access-Control-Allow-Origin", "*");
  resHeaders.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH");
  resHeaders.set("Access-Control-Allow-Headers", "*");
  resHeaders.set("Access-Control-Expose-Headers", "*");
  
  // Remove security headers that might cause issues
  resHeaders.delete("content-security-policy");
  resHeaders.delete("x-frame-options");
  resHeaders.delete("x-content-type-options");
  
  // Add proxy identification header
  resHeaders.set("X-Proxied-By", "Cloudflare-Workers-Proxy");
  
  const responseBody = await res.arrayBuffer();
  return new Response(responseBody, {
    status: res.status,
    statusText: res.statusText,
    headers: resHeaders
  });
}

// Helper function for JSON error responses
function jsonError(message, status) {
  return new Response(JSON.stringify({ error: message, status }), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*"
    }
  });
}
