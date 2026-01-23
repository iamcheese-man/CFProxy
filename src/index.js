addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request));
});

const SECRET_KEY = "A53xR14L390"; // change this to your secret key

async function handleRequest(req) {
  const urlObj = new URL(req.url);
  const pathSegments = urlObj.pathname.split("/").filter(Boolean);

  // ==== ENFORCE KEY ====
  if (pathSegments.length < 2) {
    return new Response("Unauthorized: key missing or URL missing", { status: 401 });
  }
  if (pathSegments[0] !== SECRET_KEY) {
    return new Response("Unauthorized: invalid key", { status: 401 });
  }

  // ==== DETERMINE TARGET URL ====
  let target = null;

  // Path style: /KEY/https://example.com
  target = pathSegments.slice(1).join("/");

  // Query parameter style (only works if key present in path)
  if (urlObj.searchParams.has("url")) {
    target = urlObj.searchParams.get("url");
  }

  if (!target) return new Response("Missing target URL", { status: 400 });

  // Auto-add https:// if missing
  if (!/^https?:\/\//i.test(target)) target = "https://" + target;

  // Clone headers and remove unsafe ones
  const headers = new Headers(req.headers);
  headers.delete("host");
  headers.delete("origin");
  headers.delete("referer");

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

  let res;
  try {
    res = await fetch(target, {
      method: req.method,
      headers,
      body: ["GET", "HEAD"].includes(req.method) ? null : await req.text(),
      redirect: "follow"
    });
  } catch (err) {
    return new Response(`Fetch failed: ${err.message}`, { status: 400 });
  }

  // Forward headers + CORS
  const resHeaders = new Headers(res.headers);
  resHeaders.set("Access-Control-Allow-Origin", "*");
  resHeaders.set("Access-Control-Expose-Headers", "*");

  const body = await res.arrayBuffer();
  return new Response(body, {
    status: res.status,
    statusText: res.statusText,
    headers: resHeaders
  });
}
