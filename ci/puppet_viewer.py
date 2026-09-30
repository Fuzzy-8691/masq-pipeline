#!/usr/bin/env python3
"""puppet_viewer.py — serve a local page that streams a remote Chromium
   via CDP WebSocket.

Usage:
    python3 ci/puppet_viewer.py <tunnel-url>
    python3 ci/puppet_viewer.py https://random.trycloudflare.com
"""
import sys
import threading
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler

if len(sys.argv) < 2:
    print("usage: puppet_viewer.py <tunnel-url>")
    sys.exit(1)

TUNNEL = sys.argv[1].rstrip("/")
PORT = 8765

HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Puppetmaster</title>
<style>
  body { background: #0a0a0a; margin: 0; color: #ccc;
         font-family: ui-monospace, monospace; }
  #status { padding: 10px 14px; color: #0f8; font-size: 13px;
            border-bottom: 1px solid #222; }
  #stage { display: flex; justify-content: center; padding: 20px; }
  #screen { max-width: 100%; border: 1px solid #333;
            cursor: crosshair; image-rendering: pixelated; }
  #hint { padding: 0 14px 14px; color: #666; font-size: 12px; }
</style>
</head>
<body>
<div id="status">connecting...</div>
<div id="stage"><img id="screen" /></div>
<div id="hint">click the image to click inside the remote browser</div>
<script>
const TUNNEL = "__TUNNEL__";
let ws = null;
let sessionId = null;
let meta = { deviceWidth: 1280, deviceHeight: 800 };
let nextId = 1000;

function status(msg) {
  document.getElementById("status").textContent = msg;
}

async function connect() {
  status("fetching CDP version info from " + TUNNEL + " ...");
  let version;
  try {
    version = await fetch(TUNNEL + "/json/version").then(r => r.json());
  } catch (e) {
    status("failed to fetch " + TUNNEL + "/json/version: " + e);
    return;
  }
  let wsUrl = version.webSocketDebuggerUrl || "";
  const host = new URL(TUNNEL).host;
  wsUrl = wsUrl
    .replace(/^ws:\/\/localhost:9222/, "wss://" + host)
    .replace(/^ws:\/\/127\.0\.0\.1:9222/, "wss://" + host)
    .replace(/^ws:\/\/[^\/]+/, "wss://" + host);
  status("connecting websocket → " + wsUrl);
  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    status("connected — finding page target");
    ws.send(JSON.stringify({ id: 1, method: "Target.getTargets" }));
  };
  ws.onerror = (e) => status("websocket error");
  ws.onclose = () => status("disconnected");
  ws.onmessage = handleMessage;
}

function send(method, params) {
  if (!ws || ws.readyState !== 1) return;
  const id = nextId++;
  const msg = { id, method, params: params || {} };
  if (sessionId) msg.sessionId = sessionId;
  ws.send(JSON.stringify(msg));
}

function handleMessage(ev) {
  let msg;
  try { msg = JSON.parse(ev.data); } catch { return; }

  if (msg.id === 1 && msg.result) {
    const page = msg.result.targetInfos.find(t => t.type === "page");
    if (!page) {
      status("no page target found — waiting for page...");
      setTimeout(() => ws.send(JSON.stringify({ id: 1, method: "Target.getTargets" })), 2000);
      return;
    }
    ws.send(JSON.stringify({
      id: 2, method: "Target.attachToTarget",
      params: { targetId: page.targetId, flatten: true }
    }));
  }

  if (msg.id === 2 && msg.result) {
    sessionId = msg.result.sessionId;
    status("attached — starting screencast");
    send("Page.enable");
    send("Page.startScreencast", {
      format: "jpeg", quality: 70,
      maxWidth: 1280, maxHeight: 800, everyNthFrame: 1
    });
  }

  if (msg.method === "Page.screencastFrame") {
    const data = msg.params.data;
    if (msg.params.metadata) meta = msg.params.metadata;
    document.getElementById("screen").src = "data:image/jpeg;base64," + data;
    send("Page.screencastFrameAck", { sessionId: msg.params.sessionId });
  }
}

const img = document.getElementById("screen");
img.addEventListener("click", (e) => {
  const rect = img.getBoundingClientRect();
  const x = Math.round((e.clientX - rect.left) / rect.width * meta.deviceWidth);
  const y = Math.round((e.clientY - rect.top) / rect.height * meta.deviceHeight);
  send("Input.dispatchMouseEvent", {
    type: "mousePressed", x, y, button: "left", clickCount: 1
  });
  send("Input.dispatchMouseEvent", {
    type: "mouseReleased", x, y, button: "left", clickCount: 1
  });
});

connect();
</script>
</body>
</html>"""

HTML = HTML.replace("__TUNNEL__", TUNNEL)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(HTML.encode("utf-8"))

    def log_message(self, *a, **k):
        pass


def main():
    url = f"http://localhost:{PORT}"
    print(f"serving viewer at {url}")
    print(f"remote tunnel: {TUNNEL}")
    print("press Ctrl+C to stop")
    threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nstopped")
