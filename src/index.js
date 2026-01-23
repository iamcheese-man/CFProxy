addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request));
});

const SECRET_KEY = "A53xR14L390"; // change this to your secret key

async function handleRequest(req) {
  const urlObj = new URL(req.url);
  const pathSegments = urlObj.pathname.split("/").filter(Boolean);
  
  // ==== ENFORCE KEY ====
  if (pathSegments.length < 1) {
    return new Response("Unauthorized: key missing", { status: 401 });
  }
  
  if (pathSegments[0] !== SECRET_KEY) {
    return new Response("Unauthorized: invalid key", { status: 401 });
  }
  
  // ==== DETERMINE TARGET URL ====
  let target = null;
  
  // Query parameter style
  if (urlObj.searchParams.has("url")) {
    target = urlObj.searchParams.get("url");
  }
  // Path style: /KEY/https://example.com/path
  // We need to reconstruct the URL properly, not just join with "/"
  else if (pathSegments.length > 1) {
    // Get everything after the key in the original path
    const keyLength = `/${SECRET_KEY}/`.length;
    const pathAfterKey = urlObj.pathname.substring(keyLength);
    target = pathAfterKey;
  }
  
  if (!target) {
    return new Response("Missing target URL", { status: 400 });
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
    return new Response(`Invalid target URL: ${err.message}`, { status: 400 });
  }
  
  // Clone headers and remove problematic ones
  const headers = new Headers(req.headers);
  // Remove headers that shouldn't be forwarded
  headers.delete("host"); // Will be set automatically by fetch
  headers.delete("origin");
  headers.delete("referer");
  headers.delete("cf-connecting-ip");
  headers.delete("cf-ray");
  headers.delete("cf-visitor");
  
  // Browser-like defaults
  if (!headers.has("user-agent")) {
    headers.set(
      "user-agent",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    );
  }
  if (!headers.has("accept")) {
    headers.set(
      "accept",
      "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    );
  }
  if (!headers.has("accept-language")) {
    headers.set("accept-language", "en-US,en;q=0.9");
  }
  
  let res;
  try {
    res = await fetch(targetUrl.toString(), {
      method: req.method,
      headers,
      body: ["GET", "HEAD"].includes(req.method) ? null : await req.text(),
      redirect: "follow"
    });
  } catch (err) {
    return new Response(`Fetch failed: ${err.message}`, { status: 502 });
  }
  
  // Forward headers + CORS
  const resHeaders = new Headers(res.headers);
  resHeaders.set("Access-Control-Allow-Origin", "*");
  resHeaders.set("Access-Control-Expose-Headers", "*");
  resHeaders.delete("content-security-policy");
  resHeaders.delete("x-frame-options");
  
  const body = await res.arrayBuffer();
  return new Response(body, {
    status: res.status,
    statusText: res.statusText,
    headers: resHeaders
  });
}
