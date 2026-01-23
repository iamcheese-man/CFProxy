addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(req) {
  // ==== CONFIG ====
  const SECRET_KEY = "A53xR14L390" // <-- change this to your secret key

  const urlObj = new URL(req.url)
  const pathSegments = urlObj.pathname.split("/").filter(Boolean) // split path into segments

  // ==== CHECK SECRET KEY ====
  if (pathSegments.length === 0 || pathSegments[0] !== SECRET_KEY) {
    return new Response("Unauthorized: invalid key", { status: 401 })
  }

  // ==== DETERMINE TARGET URL ====
  let targetUrl = null

  // 1️⃣ Query parameter style: /KEY/?url=https://example.com
  if (urlObj.searchParams.has("url")) {
    targetUrl = urlObj.searchParams.get("url")
  }
  // 2️⃣ Path style: /KEY/https://example.com
  else if (pathSegments.length > 1) {
    targetUrl = pathSegments.slice(1).join("/")
  }

  // No target URL?
  if (!targetUrl) {
    return new Response("Missing target URL", { status: 400 })
  }

  // Auto-add https:// if missing
  if (!/^https?:\/\//i.test(targetUrl)) {
    targetUrl = "https://" + targetUrl
  }

  try {
    // ==== FORWARD REQUEST ====
    const init = {
      method: req.method,
      headers: req.headers
    }

    // Include body if method allows
    if (req.method !== "GET" && req.method !== "HEAD") {
      init.body = await req.text()
    }

    const response = await fetch(targetUrl, init)

    // ==== CLONE HEADERS + CORS ====
    const newHeaders = new Headers(response.headers)
    newHeaders.set("Access-Control-Allow-Origin", "*")
    newHeaders.set("Access-Control-Allow-Methods", "*")
    newHeaders.set("Access-Control-Allow-Headers", "*")

    const body = await response.arrayBuffer()

    return new Response(body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders
    })
  } catch (err) {
    return new Response("Error fetching target URL: " + err.message, { status: 502 })
  }
}
