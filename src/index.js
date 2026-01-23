addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request))
})

const VALID_KEYS = ["A53xR14L390"] // Add more keys if needed
const MAX_BODY_BYTES = 10_000_000 // 10 MB max response

async function handleRequest(req) {
  // Handle CORS preflight
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "*",
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Max-Age": "86400"
      }
    })
  }

  const urlObj = new URL(req.url)
  const pathSegments = urlObj.pathname.split("/").filter(Boolean)

  // ==== CHECK SECRET KEY ====
  if (pathSegments.length === 0 || !VALID_KEYS.includes(pathSegments[0])) {
    return new Response("Unauthorized: invalid key", { status: 401 })
  }

  // ==== DETERMINE TARGET URL ====
  let target = urlObj.searchParams.get("url") || (pathSegments.length > 1 ? pathSegments.slice(1).join("/") : null)
  if (!target) return new Response("Missing target URL", { status: 400 })

  // Only allow http/https URLs
  if (!/^https?:\/\//i.test(target)) target = "https://" + target

  // ==== CLONE HEADERS ====
  const headers = new Headers(req.headers)
  headers.delete("host")
  headers.delete("origin")
  headers.delete("referer")

  if (!headers.has("user-agent")) {
    headers.set(
      "user-agent",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
  }
  if (!headers.has("accept")) {
    headers.set(
      "accept",
      "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    )
  }

  // ==== PREPARE BODY FOR METHODS THAT SUPPORT IT ====
  const methodsWithBody = ["POST", "PUT", "PATCH", "DELETE"]
  let fetchBody = null
  if (methodsWithBody.includes(req.method.toUpperCase())) {
    try {
      fetchBody = await req.arrayBuffer()
    } catch (err) {
      return new Response(`Failed to read request body: ${err.message}`, { status: 400 })
    }
  }

  let res
  try {
    res = await fetch(target, {
      method: req.method,
      headers,
      body: fetchBody,
      redirect: "follow"
    })
  } catch (err) {
    return new Response(`Fetch failed: ${err.message}`, { status: 502 })
  }

  // Forward headers + CORS
  const resHeaders = new Headers(res.headers)
  resHeaders.set("Access-Control-Allow-Origin", "*")
  resHeaders.set("Access-Control-Expose-Headers", "*")

  const body = await res.arrayBuffer()
  if (body.byteLength > MAX_BODY_BYTES) {
    return new Response("Response too large", { status: 413 })
  }

  return new Response(body, {
    status: res.status,
    statusText: res.statusText,
    headers: resHeaders
  })
}
