addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(req) {
  const SECRET_KEY = "A53xR14L390"; // <-- your enforced key

  const urlObj = new URL(req.url);
  const pathSegments = urlObj.pathname.split("/").filter(Boolean); // split path

  // ==== ENFORCE SECRET KEY ====
  if (pathSegments.length === 0 || pathSegments[0] !== SECRET_KEY) {
    return new Response("Unauthorized: invalid key", { status: 401 });
  }

  // ==== DETERMINE TARGET URL ====
  let target = null;

  // Query param style: ?url=https://example.com
  if (urlObj.searchParams.has("url")) {
    target = urlObj.searchParams.get("url");
  }
  // Path style: /KEY/https://example.com
  else if (pathSegments.length > 1) {
    target = pathSegments.slice(1).join("/");
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
    return new Response("Fetch failed: " + err.message, { status: 502 });
  }

  // Forward headers + CORS
  const resHeaders = new Headers(res.headers);
  resHeaders.set("Access-Control-Allow-Origin", "*");
  resHeaders.set("Access-Control-Expose-Headers", "*");
  resHeaders.set("Access-Control-Allow-Methods", "*");
  resHeaders.set("Access-Control-Allow-Headers", "*");

  const body = await res.arrayBuffer();
  return new Response(body, {
    status: res.status,
    statusText: res.statusText,
    headers: resHeaders
  });
}
