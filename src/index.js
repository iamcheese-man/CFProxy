addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request, event));
});

// ==================== CONFIGURATION ====================

const ALLOWED_IP_HOSTNAME = "publichomeip.duckdns.org";
const IP_CACHE_TTL = 300; // 5 minutes

// Rate limiting tiers
const RATE_LIMITS = {
  PER_IP: { limit: 60, window: 60 * 1000 },        // 60 req/min per IP
  GLOBAL: { limit: 1000, window: 60 * 1000 },      // 1000 req/min total
  BURST: { limit: 10, window: 1000 },              // 10 req/sec burst protection
};

// DDoS protection settings
const DDOS_PROTECTION = {
  ENABLE_CHALLENGE: true,           // Enable JS challenge for suspicious IPs
  ENABLE_CAPTCHA: false,            // Enable captcha (requires Turnstile)
  BLOCK_THRESHOLD: 200,             // Block IP after 200 violations
  SUSPICIOUS_PATTERNS: true,        // Detect suspicious request patterns
  MAX_REQUEST_SIZE: 10 * 1024 * 1024, // 10MB max request
};

// Cache for the allowed IP
let allowedIPCache = null;
let allowedIPCacheTime = 0;

// Global rate limit counter
let globalRequestCount = 0;
let globalWindowStart = Date.now();

// IP reputation tracking
const ipReputation = new Map(); // { ip: { violations: 0, lastSeen: timestamp, blocked: false } }

async function handleRequest(req, event) {
  const startTime = Date.now();
  const clientIP = req.headers.get("cf-connecting-ip") || "unknown";
  const cache = caches.default;
  
  // ===== 1. EARLY DEFENSES =====
  
  // Check request size (prevent large payload attacks)
  const contentLength = parseInt(req.headers.get("content-length") || "0");
  if (contentLength > DDOS_PROTECTION.MAX_REQUEST_SIZE) {
    return jsonError("Request too large", 413);
  }
  
  // Check for suspicious patterns
  if (DDOS_PROTECTION.SUSPICIOUS_PATTERNS) {
    const suspicious = detectSuspiciousRequest(req);
    if (suspicious) {
      trackViolation(clientIP, "suspicious_pattern");
      return jsonError("Suspicious request pattern detected", 403);
    }
  }
  
  // ===== 2. IP REPUTATION CHECK =====
  const reputation = getIPReputation(clientIP);
  
  if (reputation.blocked) {
    return jsonError("IP temporarily blocked due to violations", 403);
  }
  
  if (reputation.violations > DDOS_PROTECTION.BLOCK_THRESHOLD / 2) {
    // IP is getting suspicious, add challenge
    if (DDOS_PROTECTION.ENABLE_CHALLENGE) {
      const hasValidChallenge = await verifyChallenge(req, clientIP);
      if (!hasValidChallenge) {
        return getChallengeResponse(clientIP);
      }
    }
  }
  
  // ===== 3. GLOBAL RATE LIMITING =====
  const now = Date.now();
  
  if (now - globalWindowStart > RATE_LIMITS.GLOBAL.window) {
    globalRequestCount = 1;
    globalWindowStart = now;
  } else {
    globalRequestCount++;
  }
  
  if (globalRequestCount > RATE_LIMITS.GLOBAL.limit) {
    trackViolation(clientIP, "global_rate_limit");
    return jsonError("Global rate limit exceeded - DDoS protection active", 429);
  }
  
  // ===== 4. BURST PROTECTION =====
  const burstKey = new Request(`https://burst.internal/${clientIP}`);
  const burstCache = await cache.match(burstKey);
  let burstState = burstCache ? await burstCache.json() : { count: 0, start: now };
  
  if (now - burstState.start > RATE_LIMITS.BURST.window) {
    burstState = { count: 1, start: now };
  } else {
    burstState.count++;
  }
  
  if (burstState.count > RATE_LIMITS.BURST.limit) {
    trackViolation(clientIP, "burst_limit");
    return jsonError("Burst rate limit exceeded", 429);
  }
  
  const burstResp = new Response(JSON.stringify(burstState), {
    status: 200,
    headers: { "Cache-Control": "max-age=1" }
  });
  event.waitUntil(cache.put(burstKey, burstResp.clone()));
  
  // ===== 5. PER-IP RATE LIMITING =====
  const rateLimitKey = new Request(`https://ratelimit.internal/${clientIP}`);
  const cachedResp = await cache.match(rateLimitKey);
  let state = cachedResp ? await cachedResp.json() : { count: 0, start: now };
  
  if (now - state.start > RATE_LIMITS.PER_IP.window) {
    state.count = 1;
    state.start = now;
  } else {
    state.count++;
  }
  
  if (state.count > RATE_LIMITS.PER_IP.limit) {
    trackViolation(clientIP, "per_ip_rate_limit");
    return jsonError("Rate limit exceeded (60 requests per minute)", 429);
  }
  
  const stateResp = new Response(JSON.stringify(state), {
    status: 200,
    headers: { "Cache-Control": "max-age=60" }
  });
  event.waitUntil(cache.put(rateLimitKey, stateResp.clone()));
  
  // ===== 6. CORS PREFLIGHT =====
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
  
  // ===== 7. DEBUG ENDPOINTS =====
  if (urlObj.pathname === '/_debug_ip') {
    const allowedIP = await getAllowedIPViaDNS();
    return new Response(JSON.stringify({
      yourIP: clientIP,
      allowedIP: allowedIP,
      hostname: ALLOWED_IP_HOSTNAME,
      match: clientIP === allowedIP,
      reputation: reputation,
      globalRate: globalRequestCount,
      processingTime: Date.now() - startTime,
    }, null, 2), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
      },
    });
  }
  
  if (urlObj.pathname === '/_stats') {
    return new Response(JSON.stringify({
      globalRequests: globalRequestCount,
      globalWindow: RATE_LIMITS.GLOBAL.window / 1000,
      trackedIPs: ipReputation.size,
      blockedIPs: Array.from(ipReputation.entries())
        .filter(([_, rep]) => rep.blocked)
        .map(([ip, rep]) => ({ ip, violations: rep.violations })),
    }, null, 2), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
      },
    });
  }
  
  // ===== 8. IP WHITELIST CHECK =====
  const allowedIP = await getAllowedIPViaDNS();
  
  if (!allowedIP) {
    return jsonError(`Unable to resolve ${ALLOWED_IP_HOSTNAME} via DNS`, 503);
  }
  
  if (clientIP !== allowedIP) {
    trackViolation(clientIP, "not_whitelisted");
    
    if (req.method === "GET") {
      return new Response(getBlockedHTML(clientIP, allowedIP), {
        status: 403,
        headers: {
          "Content-Type": "text/html",
          "Access-Control-Allow-Origin": "*",
        },
      });
    }
    return jsonError(`Access denied. Your IP (${clientIP}) is not authorized.`, 403);
  }
  
  // ===== 9. DETERMINE TARGET URL =====
  let target;
  
  if (urlObj.searchParams.has("url")) {
    target = urlObj.searchParams.get("url");
  } else {
    const path = urlObj.pathname.substring(1);
    if (path) {
      target = path;
      if (urlObj.search && urlObj.search !== '?') {
        target += urlObj.search;
      }
    }
  }
  
  if (!target) {
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
  
  // ===== 10. BLOCK PRIVATE IPS =====
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
  
  // ===== 11. BUILD HEADERS =====
  const headers = new Headers();
  for (const [key, value] of req.headers.entries()) {
    if (!["host", "origin", "referer", "x-forwarded-for", "x-real-ip",
          "cf-connecting-ip", "cf-ray", "cf-visitor", "cf-ipcountry"].includes(key.toLowerCase())) {
      headers.set(key, value);
    }
  }
  
  if (clientIP) {
    headers.set("cf-connecting-ip", clientIP);
    headers.set("x-forwarded-for", clientIP);
  }
  
  headers.set("host", targetUrl.host);
  headers.set("user-agent", headers.get("user-agent") ||
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
  headers.set("accept", headers.get("accept") ||
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
  
  // ===== 12. FETCH TARGET =====
  let body = null;
  if (!["GET", "HEAD"].includes(req.method)) {
    body = await req.arrayBuffer();
  }
  
  if (req.method === "GET") {
    const cachedResponse = await cache.match(req);
    if (cachedResponse) return cachedResponse;
  }
  
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
  
  // ===== 13. FORWARD RESPONSE =====
  const resHeaders = new Headers(res.headers);
  resHeaders.set("Access-Control-Allow-Origin", "*");
  resHeaders.set("Access-Control-Allow-Headers", "*");
  resHeaders.set("Access-Control-Expose-Headers", "*");
  resHeaders.set("X-Proxied-By", "Cloudflare Worker");
  resHeaders.set("X-Processing-Time", `${Date.now() - startTime}ms`);
  
  resHeaders.delete("content-security-policy");
  resHeaders.delete("x-frame-options");
  resHeaders.delete("x-content-type-options");
  
  const finalResponse = new Response(res.body, {
    status: res.status,
    statusText: res.statusText,
    headers: resHeaders,
  });
  
  if (req.method === "GET" && res.status >= 200 && res.status < 300) {
    event.waitUntil(cache.put(req, finalResponse.clone()));
  }
  
  return finalResponse;
}

// ==================== DDOS PROTECTION FUNCTIONS ====================

function detectSuspiciousRequest(req) {
  const url = new URL(req.url);
  const userAgent = req.headers.get("user-agent") || "";
  
  // Only check the path and query, not the protocol
  const pathAndQuery = (url.pathname + url.search).toLowerCase();
  
  // Check for common attack patterns
  const suspiciousPatterns = [
    /\.\.\//,                         // Path traversal (../)
    /<script|javascript:|onerror=/i,  // XSS attempts
    /union.*select|drop.*table/i,     // SQL injection
    /\${.*}|<%.*%>/,                  // Template injection
    /%00|%0[ad]/i,                    // Null byte injection
  ];
  
  for (const pattern of suspiciousPatterns) {
    if (pattern.test(pathAndQuery)) return true;
  }
  
  // Check for suspicious user agents (but allow legitimate browsers)
  if (userAgent && userAgent.length > 0) {
    const suspiciousUAs = [
      /bot/i,
      /crawler/i,
      /spider/i,
      /scraper/i,
      /curl/i,
      /wget/i,
      /python/i,
    ];
    
    // Only flag if it's OBVIOUSLY a bot, not a real browser
    const isLikelyBot = suspiciousUAs.some(pattern => pattern.test(userAgent)) &&
                        !userAgent.includes('Mozilla') &&
                        !userAgent.includes('Chrome') &&
                        !userAgent.includes('Safari');
    
    if (isLikelyBot) return true;
  }
  
  // Check for excessive query parameters (potential parameter pollution)
  if (url.searchParams.toString().length > 2000) return true;
  
  return false;
}

function trackViolation(ip, reason) {
  if (!ipReputation.has(ip)) {
    ipReputation.set(ip, {
      violations: 0,
      lastSeen: Date.now(),
      blocked: false,
      reasons: []
    });
  }
  
  const rep = ipReputation.get(ip);
  rep.violations++;
  rep.lastSeen = Date.now();
  rep.reasons.push({ reason, time: Date.now() });
  
  // Block if threshold exceeded
  if (rep.violations > DDOS_PROTECTION.BLOCK_THRESHOLD) {
    rep.blocked = true;
    console.log(`IP ${ip} blocked after ${rep.violations} violations`);
  }
  
  // Cleanup old entries (keep last 1000 IPs)
  if (ipReputation.size > 1000) {
    const oldest = Array.from(ipReputation.entries())
      .sort((a, b) => a[1].lastSeen - b[1].lastSeen)[0];
    ipReputation.delete(oldest[0]);
  }
}

function getIPReputation(ip) {
  if (!ipReputation.has(ip)) {
    return { violations: 0, blocked: false, lastSeen: null };
  }
  
  const rep = ipReputation.get(ip);
  
  // Unblock after 1 hour
  if (rep.blocked && Date.now() - rep.lastSeen > 3600000) {
    rep.blocked = false;
    rep.violations = Math.floor(rep.violations / 2);
  }
  
  return rep;
}

async function verifyChallenge(req, ip) {
  const challengeCookie = req.headers.get("cookie") || "";
  const match = challengeCookie.match(/cf_challenge=([^;]+)/);
  
  if (!match) return false;
  
  const token = match[1];
  const expected = generateChallengeToken(ip);
  
  return token === expected;
}

function generateChallengeToken(ip) {
  // Simple token generation (use crypto.subtle for production)
  return btoa(ip + ":" + Date.now().toString(36));
}

function getChallengeResponse(ip) {
  const token = generateChallengeToken(ip);
  
  return new Response(`
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Challenge - DDoS Protection</title>
  <style>
    body {
      font-family: system-ui;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }
    .box {
      background: white;
      padding: 40px;
      border-radius: 12px;
      text-align: center;
      max-width: 400px;
    }
    .spinner {
      border: 4px solid #f3f3f3;
      border-top: 4px solid #667eea;
      border-radius: 50%;
      width: 50px;
      height: 50px;
      animation: spin 1s linear infinite;
      margin: 20px auto;
    }
    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }
  </style>
</head>
<body>
  <div class="box">
    <h2>🛡️ DDoS Protection</h2>
    <p>Verifying your browser...</p>
    <div class="spinner"></div>
  </div>
  <script>
    // Set challenge cookie and reload
    document.cookie = "cf_challenge=${token}; path=/; max-age=3600";
    setTimeout(() => location.reload(), 2000);
  </script>
</body>
</html>`, {
    status: 403,
    headers: { "Content-Type": "text/html" }
  });
}

// ===== DNS RESOLUTION =====

async function getAllowedIPViaDNS() {
  const now = Date.now();
  
  if (allowedIPCache && (now - allowedIPCacheTime) < (IP_CACHE_TTL * 1000)) {
    return allowedIPCache;
  }
  
  try {
    const dnsUrl = `https://cloudflare-dns.com/dns-query?name=${ALLOWED_IP_HOSTNAME}&type=A`;
    
    const response = await fetch(dnsUrl, {
      headers: { 'Accept': 'application/dns-json' },
      signal: AbortSignal.timeout(5000),
    });
    
    if (!response.ok) return allowedIPCache;
    
    const dnsData = await response.json();
    
    if (dnsData.Answer && dnsData.Answer.length > 0) {
      const aRecord = dnsData.Answer.find(record => record.type === 1);
      
      if (aRecord && aRecord.data) {
        const ip = aRecord.data;
        
        if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
          allowedIPCache = ip;
          allowedIPCacheTime = now;
          return ip;
        }
      }
    }
    
    return allowedIPCache;
    
  } catch (err) {
    return allowedIPCache;
  }
}

// ===== HELPER FUNCTIONS =====

function jsonError(message, status = 400) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    },
  });
}

function getWelcomeHTML(clientIP, allowedIP) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>DDoS-Protected Proxy</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: system-ui;
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
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      max-width: 600px;
      width: 100%;
      padding: 40px;
    }
    h1 { color: #333; margin-bottom: 10px; }
    .status {
      background: #e8f5e9;
      border: 2px solid #4caf50;
      color: #2e7d32;
      padding: 16px;
      border-radius: 8px;
      margin: 20px 0;
    }
    .protection-badge {
      display: inline-block;
      background: #ff9800;
      color: white;
      padding: 4px 12px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: bold;
      margin-left: 10px;
    }
    input { width: 100%; padding: 12px; border: 2px solid #e0e0e0; border-radius: 8px; margin: 10px 0; }
    button {
      width: 100%;
      padding: 14px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      border: none;
      border-radius: 8px;
      font-size: 16px;
      cursor: pointer;
    }
    .stats { margin-top: 20px; font-size: 13px; color: #666; }
    a { color: #1976d2; text-decoration: none; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🚀 DDoS-Protected Proxy<span class="protection-badge">PROTECTED</span></h1>
    <div class="status">
      ✅ Authorized IP: <code>${clientIP}</code>
    </div>
    <form onsubmit="event.preventDefault(); let u=document.getElementById('url').value; if(!/^https?:\\/\\//.test(u))u='https://'+u; location.href='/'+u;">
      <input type="text" id="url" placeholder="https://example.com" required />
      <button type="submit">Browse Through Proxy</button>
    </form>
    <div class="stats">
      🛡️ <strong>Active Protection:</strong> Rate limiting, burst protection, IP reputation<br>
      📊 <a href="/_stats">View Stats</a> | <a href="/_debug_ip">Debug Info</a>
    </div>
  </div>
</body>
</html>`;
}

function getBlockedHTML(clientIP, allowedIP) {
  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Access Denied</title>
  <style>
    body { font-family: system-ui; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; background: linear-gradient(135deg, #f44336 0%, #e91e63 100%); }
    .container { background: white; padding: 40px; border-radius: 12px; text-align: center; max-width: 500px; }
    h1 { color: #d32f2f; }
    .ip { background: #ffebee; padding: 20px; border-radius: 8px; margin: 20px 0; }
    code { background: white; padding: 4px 8px; border-radius: 4px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🚫 Access Denied</h1>
    <p>Your IP is not whitelisted</p>
    <div class="ip">
      <strong>Your IP:</strong> <code>${clientIP}</code><br>
      <strong>Allowed IP:</strong> <code>${allowedIP}</code>
    </div>
  </div>
</body>
</html>`;
}
