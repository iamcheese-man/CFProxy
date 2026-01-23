export default {
  async fetch(req) {
    // CORS preflight
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

    const url = new URL(req.url)
    const target = url.searchParams.get("url")

    if (!target) {
      return new Response("Missing ?url=", { status: 400 })
    }

    // Clone headers
    const headers = new Headers(req.headers)
    headers.delete("host")
    headers.delete("origin")
    headers.delete("referer")

    // Browser-like defaults
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

    const proxyReq = new Request(target, {
      method: req.method,
      headers,
      body: ["GET", "HEAD"].includes(req.method) ? null : req.body,
      redirect: "follow"
    })

    const res = await fetch(proxyReq)

    const resHeaders = new Headers(res.headers)
    resHeaders.set("Access-Control-Allow-Origin", "*")
    resHeaders.set("Access-Control-Expose-Headers", "*")

    return new Response(res.body, {
      status: res.status,
      headers: resHeaders
    })
  }
}
