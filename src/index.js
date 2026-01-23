addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request))
})

const SECRET_KEY = "A53xR14L390" // <-- change this to your secret key

async function handleRequest(req) {
  const urlObj = new URL(req.url)
  const pathSegments = urlObj.pathname.split("/").filter(Boolean)

  // ==== SECRET KEY CHECK ====
  if (pathSegments.length === 0 || pathSegments[0] !== SECRET_KEY) {
    return jsonResponse({ error: "Unauthorized: invalid key" }, 401)
  }

  // ==== PRE-FLIGHT HANDLING ====
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

  // ==== DETERMINE TARGET URL ====
  let target = urlObj.searchParams.get("url") || (pathSegments.length > 1 ? pathSegments.slice(1).join("/") : null)
  if (!target) return jsonResponse({ error: "Missing target URL" }, 400)

  if (!/^https?:\/\//i.test(target)) target = "https://" + target

  // ==== FORWARD HEADERS ====
  const headers = new Headers(req.headers)
  headers.delete("host")
  headers.delete("origin")
  headers.delete("referer")

  if (!headers.has("user-agent")) headers.set(
    "user-agent",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
  )
  if (!headers.has("accept")) headers.set(
    "accept",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
  )

  let res
  try {
    res = await fetch(target, {
      method: req.method,
      headers,
      body: ["GET", "HEAD"].includes(req.method) ? null : await req.text(),
      redirect: "follow"
    })
  } catch (err) {
    return jsonResponse({ error: "Fetch failed: " + err.message }, 502)
  }

  // ==== PROCESS RESPONSE ====
  const resHeaders = {}
  res.headers.forEach((v, k) => { resHeaders[k] = v })

  let bodyContent
  const contentType = res.headers.get("content-type") || ""
  try {
    if (contentType.startsWith("application/json") || contentType.startsWith("text/")) {
      bodyContent = await res.text()
    } else {
      // Binary content -> base64
      const arrayBuffer = await res.arrayBuffer()
      bodyContent = arrayBufferToBase64(arrayBuffer)
    }
  } catch (err) {
    bodyContent = null
  }

  return jsonResponse({
    status: res.status,
    statusText: res.statusText,
    headers: resHeaders,
    body: bodyContent,
    isBase64: !contentType.startsWith("text/") && !contentType.includes("json")
  })
}

// ==== HELPERS ====
function jsonResponse(data, status = 200) {
  const headers = new Headers({
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Expose-Headers": "*"
  })
  return new Response(JSON.stringify(data, null, 2), { status, headers })
}

function arrayBufferToBase64(buffer) {
  let binary = ''
  const bytes = new Uint8Array(buffer)
  const len = bytes.byteLength
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
}
