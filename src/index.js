addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(req) {
  let urlStr

  // Try query parameter first
  try {
    const urlObj = new URL(req.url)
    urlStr = urlObj.searchParams.get("url")
  } catch (e) {
    // ignore
  }

  // If no query, try path-style
  if (!urlStr) {
    urlStr = req.url.replace(/^https?:\/\/[^\/]+\/?/, "") // strip domain + leading slash
  }

  // If still empty, return error
  if (!urlStr) {
    return new Response("Missing target URL", { status: 400 })
  }

  // Auto-add https:// if missing
  if (!/^https?:\/\//i.test(urlStr)) {
    urlStr = "https://" + urlStr
  }

  try {
    // Forward the request
    const init = {
      method: req.method,
      headers: req.headers
    }

    // Only include body if method allows
    if (req.method !== "GET" && req.method !== "HEAD") {
      init.body = await req.text()
    }

    const response = await fetch(urlStr, init)

    // Clone headers
    const newHeaders = new Headers(response.headers)
    // Optional: add CORS headers
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
