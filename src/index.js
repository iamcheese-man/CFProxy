addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request, event));
});

const RATE_LIMIT = 61;
const RATE_WINDOW = 60 * 1000; // 60 seconds
const ALLOWED_IP_HOSTNAME = "publichomeip.duckdns.org";
const IP_CACHE_TTL = 300; // Cache DNS result for 5 minutes

// Cache for the allowed IP
let allowedIPCache = null;
let allowedIPCacheTime = 0;

async function handleRequest(req, event) {
  // ===== Get client IP =====
  const clientIP = req.headers.get("cf-connecting-ip") || "unknown";
  
  // ===== Rate limiting =====
  const cacheKey = new Request(`https://ratelimit.internal/${clientIP}`);
  const now = Date.now();
  const cache = caches.default;

  const cachedResp = await cache.match(cacheKey);
  let state = cachedResp ? await cachedResp.json() : { count: 0, start: now };

  if (now - state.start > RATE_WINDOW) {
    state.count = 1;
    state.start = now;
  } else {
    state.count++;
  }

  if (state.count > RATE_LIMIT) {
    return jsonError("Rate limit exceeded (61 requests per minute)", 429);
  }

  const stateResp = new Response(JSON.stringify(state), { 
    status: 200,
    headers: {
      "Cache-Control": "max-age=60"
    }
  });
  event.waitUntil(cache.put(cacheKey, stateResp.clone()));

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

  const urlObj = new URL(req.url);
  
  // ===== Debug endpoint to check allowed IP =====
  if (urlObj.pathname === '/_debug_ip') {
    const allowedIP = await getAllowedIPViaDNS();
    return new Response(JSON.stringify({
      yourIP: clientIP,
      allowedIP: allowedIP,
      hostname: ALLOWED_IP_HOSTNAME,
      match: clientIP === allowedIP,
      cacheAge: allowedIPCacheTime ? Math.floor((Date.now() - allowedIPCacheTime) / 1000) : null,
    }, null, 2), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
      },
    });
  }
  
  // ===== Check IP Authorization =====
  const allowedIP = await getAllowedIPViaDNS();
  
  if (!allowedIP) {
    return jsonError(`Unable to resolve ${ALLOWED_IP_HOSTNAME} via DNS`, 503);
  }
  
  if (clientIP !== allowedIP) {
    // Return an informative blocked page
    if (req.method === "GET") {
      return new Response(getBlockedHTML(clientIP, allowedIP), {
        status: 403,
        headers: {
          "Content-Type": "text/html",
          "Access-Control-Allow-Origin": "*",
        },
      });
    }
    return jsonError(`Access denied. Your IP (${clientIP}) is not authorized. Allowed IP: ${allowedIP}`, 403);
  }

  // ===== Determine target URL =====
  let target;
  
  if (urlObj.searchParams.has("url")) {
    target = urlObj.searchParams.get("url");
  } else {
    // Use the path as the target URL
    const path = urlObj.pathname.substring(1); // Remove leading /
    if (path) {
      target = path;
      // Add back the search params
      if (urlObj.search && urlObj.search !== '?') {
        target += urlObj.search;
      }
    }
  }

  if (!target) {
    // Show welcome page
    if (req.method === "GET") {
      return new Response(getWelcomeHTML(clientIP, allowedIP), {
        status: 200,
        headers: {
          "Content-Type": "text/html",
          "Access-Control-Allow-Origin": "*",
        },
      });
    }
    return jsonError("Missing target URL", 400);
  }

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
  resHeaders.set("X-Allowed-IP", allowedIP);

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

// ===== Resolve IP via DNS (using Cloudflare DNS over HTTPS) =====
async function getAllowedIPViaDNS() {
  const now = Date.now();
  
  // Return cached IP if still valid
  if (allowedIPCache && (now - allowedIPCacheTime) < (IP_CACHE_TTL * 1000)) {
    return allowedIPCache;
  }
  
  try {
    // Use Cloudflare's DNS-over-HTTPS API
    const dnsUrl = `https://cloudflare-dns.com/dns-query?name=${ALLOWED_IP_HOSTNAME}&type=A`;
    
    const response = await fetch(dnsUrl, {
      headers: {
        'Accept': 'application/dns-json'
      },
      signal: AbortSignal.timeout(5000),
    });
    
    if (!response.ok) {
      console.error(`DNS query failed: ${response.status}`);
      return allowedIPCache; // Return cached IP if available
    }
    
    const dnsData = await response.json();
    
    // Check if we got a valid answer
    if (dnsData.Answer && dnsData.Answer.length > 0) {
      // Get the first A record
      const aRecord = dnsData.Answer.find(record => record.type === 1); // Type 1 = A record
      
      if (aRecord && aRecord.data) {
        const ip = aRecord.data;
        
        // Validate IP format
        if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
          console.log(`DNS resolved ${ALLOWED_IP_HOSTNAME} to ${ip}`);
          allowedIPCache = ip;
          allowedIPCacheTime = now;
          return ip;
        }
      }
    }
    
    console.error(`No valid A record found for ${ALLOWED_IP_HOSTNAME}`);
    return allowedIPCache;
    
  } catch (err) {
    console.error(`DNS resolution error: ${err.message}`);
    return allowedIPCache; // Return cached IP if available
  }
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

// ===== Helper: Welcome page HTML =====
function getWelcomeHTML(clientIP, allowedIP) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Cloudflare Proxy - Welcome</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: white;
      border-radius: 12px;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
      max-width: 600px;
      width: 100%;
      padding: 40px;
    }
    h1 {
      color: #333;
      margin-bottom: 10px;
      font-size: 28px;
    }
    .subtitle {
      color: #666;
      margin-bottom: 30px;
      font-size: 14px;
    }
    .status {
      background: #e8f5e9;
      border: 2px solid #4caf50;
      color: #2e7d32;
      padding: 16px;
      border-radius: 8px;
      margin-bottom: 30px;
      font-weight: 500;
    }
    .form-group {
      margin-bottom: 20px;
    }
    label {
      display: block;
      margin-bottom: 8px;
      color: #333;
      font-weight: 500;
      font-size: 14px;
    }
    input[type="text"] {
      width: 100%;
      padding: 12px 16px;
      border: 2px solid #e0e0e0;
      border-radius: 8px;
      font-size: 14px;
      transition: border-color 0.3s;
    }
    input[type="text"]:focus {
      outline: none;
      border-color: #667eea;
    }
    button {
      width: 100%;
      padding: 14px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      border: none;
      border-radius: 8px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: transform 0.2s, box-shadow 0.2s;
    }
    button:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 20px rgba(102, 126, 234, 0.4);
    }
    button:active {
      transform: translateY(0);
    }
    .info {
      background: #e3f2fd;
      border: 1px solid #90caf9;
      color: #1976d2;
      padding: 16px;
      border-radius: 8px;
      margin-top: 30px;
      font-size: 13px;
      line-height: 1.6;
    }
    .info h3 {
      margin-bottom: 12px;
      font-size: 15px;
    }
    .info ul {
      margin-left: 20px;
      margin-top: 8px;
    }
    .info li {
      margin: 6px 0;
    }
    .code {
      background: #f5f5f5;
      padding: 3px 8px;
      border-radius: 4px;
      font-family: 'Courier New', monospace;
      font-size: 12px;
      color: #d32f2f;
    }
    .ip-badge {
      display: inline-block;
      background: #4caf50;
      color: white;
      padding: 4px 12px;
      border-radius: 20px;
      font-family: 'Courier New', monospace;
      font-size: 13px;
      font-weight: bold;
    }
    .debug-link {
      display: inline-block;
      margin-top: 10px;
      color: #2e7d32;
      text-decoration: none;
      font-size: 12px;
    }
    .debug-link:hover {
      text-decoration: underline;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🚀 Cloudflare Proxy</h1>
    <p class="subtitle">DNS-Based IP Whitelist</p>
    
    <div class="status">
      ✅ Access granted for IP: <span class="ip-badge">${clientIP}</span>
      <br>
      <a href="/_debug_ip" class="debug-link" target="_blank">🔍 Debug IP Info</a>
    </div>
    
    <form id="proxyForm">
      <div class="form-group">
        <label for="url">Target URL</label>
        <input 
          type="text" 
          id="url" 
          name="url" 
          placeholder="https://example.com or example.com"
          required
        />
      </div>
      
      <button type="submit">Browse Through Proxy</button>
    </form>
    
    <div class="info">
      <h3>📖 Usage Instructions</h3>
      <ul>
        <li><strong>Web Form:</strong> Enter any URL above</li>
        <li><strong>Direct URL:</strong> <span class="code">${self.location.origin}/https://example.com</span></li>
        <li><strong>Query Parameter:</strong> <span class="code">${self.location.origin}/?url=https://example.com</span></li>
      </ul>
      <p style="margin-top: 12px;">
        <strong>🔒 Security:</strong> Whitelisted IP resolved via DNS from <code>${ALLOWED_IP_HOSTNAME}</code> (currently: <code>${allowedIP}</code>)
      </p>
    </div>
  </div>

  <script>
    const form = document.getElementById('proxyForm');
    const urlInput = document.getElementById('url');

    const params = new URLSearchParams(window.location.search);
    if (params.has('url')) {
      urlInput.value = params.get('url');
    }

    form.addEventListener('submit', (e) => {
      e.preventDefault();
      
      let url = urlInput.value.trim();
      
      if (!url) {
        alert('Please enter a target URL');
        return;
      }
      
      if (!/^https?:\/\//i.test(url)) {
        url = 'https://' + url;
      }
      
      try {
        new URL(url);
        window.location.href = window.location.origin + '/' + url;
      } catch (err) {
        alert('Invalid URL: ' + err.message);
      }
    });
  </script>
</body>
</html>`;
}

// ===== Helper: Blocked page HTML =====
function getBlockedHTML(clientIP, allowedIP) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Access Denied - IP Not Whitelisted</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      background: linear-gradient(135deg, #f44336 0%, #e91e63 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: white;
      border-radius: 12px;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
      max-width: 500px;
      width: 100%;
      padding: 40px;
      text-align: center;
    }
    .icon {
      font-size: 64px;
      margin-bottom: 20px;
    }
    h1 {
      color: #d32f2f;
      margin-bottom: 10px;
      font-size: 28px;
    }
    .subtitle {
      color: #666;
      margin-bottom: 30px;
      font-size: 14px;
    }
    .ip-info {
      background: #ffebee;
      border: 2px solid #ef5350;
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 20px;
      text-align: left;
    }
    .ip-row {
      margin: 10px 0;
      font-size: 14px;
    }
    .ip-label {
      font-weight: 600;
      color: #d32f2f;
      display: inline-block;
      width: 120px;
    }
    .ip-value {
      font-family: 'Courier New', monospace;
      background: white;
      padding: 4px 8px;
      border-radius: 4px;
      color: #333;
    }
    .info {
      background: #e3f2fd;
      border: 1px solid #90caf9;
      color: #1976d2;
      padding: 16px;
      border-radius: 8px;
      margin-top: 20px;
      font-size: 13px;
      text-align: left;
      line-height: 1.6;
    }
    .debug-link {
      display: inline-block;
      margin-top: 15px;
      padding: 10px 20px;
      background: #1976d2;
      color: white;
      text-decoration: none;
      border-radius: 6px;
      font-size: 14px;
    }
    .debug-link:hover {
      background: #1565c0;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="icon">🚫</div>
    <h1>Access Denied</h1>
    <p class="subtitle">Your IP address is not whitelisted</p>
    
    <div class="ip-info">
      <div class="ip-row">
        <span class="ip-label">Your IP:</span>
        <span class="ip-value">${clientIP}</span>
      </div>
      <div class="ip-row">
        <span class="ip-label">Allowed IP:</span>
        <span class="ip-value">${allowedIP}</span>
      </div>
      <div class="ip-row">
        <span class="ip-label">DNS Hostname:</span>
        <span class="ip-value">${ALLOWED_IP_HOSTNAME}</span>
      </div>
    </div>
    
    <a href="/_debug_ip" class="debug-link">🔍 View Debug Info</a>
    
    <div class="info">
      <strong>ℹ️ Information:</strong><br>
      This proxy resolves the allowed IP via DNS from <code>${ALLOWED_IP_HOSTNAME}</code>. 
      The DNS A record must point to your current public IP address.
    </div>
  </div>
</body>
</html>`;
}
