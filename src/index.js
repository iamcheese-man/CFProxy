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

  // ===== Check authentication header =====
  const authHeader = req.headers.get("X-CFProxy-Auth");
  
  if (!authHeader || authHeader !== SECRET_KEY) {
    // If it's a GET request without auth, return HTML password form
    if (req.method === "GET") {
      return new Response(getPasswordHTML(), {
        status: 200,
        headers: {
          "Content-Type": "text/html",
          "Access-Control-Allow-Origin": "*",
        },
      });
    }
    // For other methods, return unauthorized error
    return jsonError("Unauthorized: missing or invalid X-CFProxy-Auth header", 401);
  }

  // ===== Determine target URL =====
  const urlObj = new URL(req.url);
  let target;
  
  if (urlObj.searchParams.has("url")) {
    target = urlObj.searchParams.get("url");
  } else {
    // Use the path as the target URL
    target = urlObj.pathname.substring(1) + urlObj.search; // Remove leading /
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

  // ===== Build headers (strip X-CFProxy-Auth) =====
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
      "cf-ipcountry",
      "x-cfproxy-auth" // Strip the auth header
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

// ===== Helper: Password input HTML =====
function getPasswordHTML() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Cloudflare Proxy - Authentication Required</title>
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
      max-width: 500px;
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
    input[type="text"],
    input[type="password"] {
      width: 100%;
      padding: 12px 16px;
      border: 2px solid #e0e0e0;
      border-radius: 8px;
      font-size: 14px;
      transition: border-color 0.3s;
    }
    input[type="text"]:focus,
    input[type="password"]:focus {
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
    .error {
      background: #fee;
      border: 1px solid #fcc;
      color: #c33;
      padding: 12px;
      border-radius: 8px;
      margin-bottom: 20px;
      font-size: 14px;
      display: none;
    }
    .info {
      background: #e3f2fd;
      border: 1px solid #90caf9;
      color: #1976d2;
      padding: 12px;
      border-radius: 8px;
      margin-top: 20px;
      font-size: 13px;
    }
    .code {
      background: #f5f5f5;
      padding: 2px 6px;
      border-radius: 4px;
      font-family: 'Courier New', monospace;
      font-size: 12px;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🔒 Proxy Authentication</h1>
    <p class="subtitle">Enter your credentials to access the proxy service</p>
    
    <div id="error" class="error"></div>
    
    <form id="proxyForm">
      <div class="form-group">
        <label for="url">Target URL</label>
        <input 
          type="text" 
          id="url" 
          name="url" 
          placeholder="https://example.com"
          required
        />
      </div>
      
      <div class="form-group">
        <label for="password">Proxy Password</label>
        <input 
          type="password" 
          id="password" 
          name="password" 
          placeholder="Enter your proxy password"
          required
        />
      </div>
      
      <button type="submit">Access URL</button>
    </form>
    
    <div class="info">
      <strong>API Usage:</strong> Add <span class="code">X-CFProxy-Auth</span> header with your password to programmatically access this proxy.
    </div>
  </div>

  <script>
    const form = document.getElementById('proxyForm');
    const errorDiv = document.getElementById('error');
    const urlInput = document.getElementById('url');
    const passwordInput = document.getElementById('password');

    // Pre-fill URL from query parameter if present
    const params = new URLSearchParams(window.location.search);
    if (params.has('url')) {
      urlInput.value = params.get('url');
    }

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      errorDiv.style.display = 'none';
      
      const url = urlInput.value.trim();
      const password = passwordInput.value;
      
      if (!url) {
        showError('Please enter a target URL');
        return;
      }
      
      if (!password) {
        showError('Please enter your proxy password');
        return;
      }
      
      try {
        // Make request with auth header
        const proxyUrl = window.location.origin + '/' + url;
        const response = await fetch(proxyUrl, {
          method: 'GET',
          headers: {
            'X-CFProxy-Auth': password
          }
        });
        
        if (response.ok) {
          // Redirect to the proxied content
          window.location.href = proxyUrl + '?auth=' + encodeURIComponent(password);
        } else {
          const data = await response.json().catch(() => ({}));
          showError(data.error || 'Authentication failed. Please check your password.');
        }
      } catch (err) {
        showError('Request failed: ' + err.message);
      }
    });
    
    function showError(message) {
      errorDiv.textContent = message;
      errorDiv.style.display = 'block';
    }
  </script>
</body>
</html>`;
}
