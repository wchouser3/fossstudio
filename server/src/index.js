import express from "express";
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { config, panelDomains } from "./config.js";
import { startMediasoup } from "./media.js";
import { attachSignaling } from "./signaling.js";
import { api } from "./api.js";
import { isAuthedRequest } from "./auth.js";
import { scheduleDailyBackups } from "./ops.js";
import { initPush } from "./push.js";
import { findById } from "./users.js";
import { redeemLink } from "./loginlinks.js";
import { setAuthCookie } from "./auth.js";

const app = express();
app.disable("x-powered-by");

const FRAME_ANCESTORS = String(process.env.FRAME_ANCESTORS || "").trim()
  .split(/\s+/).filter((o) => /^https:\/\/[a-z0-9.*-]+(:\d+)?$/i.test(o)).join(" ");

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  // Framing is refused unless FRAME_ANCESTORS names who may: a panel
  // that manages this studio and shows it inside its own pages, say.
  // With it set, the browser's older X-Frame-Options header is left off
  // - it cannot express "these origins only" and would contradict the
  // CSP that can.
  if (!FRAME_ANCESTORS) res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "same-origin");
  res.setHeader("Permissions-Policy", "camera=(self), microphone=(self), geolocation=()");
  // Content Security Policy: everything loads from our own origin. No
  // inline scripts (they were externalised); inline styles are still
  // used as element style= attributes. blob:/data: cover the audio
  // worklet and canvas-drawn banner images; wss: is the signaling
  // socket. frame-ancestors none double-locks against clickjacking.
  res.setHeader("Content-Security-Policy", [
    "default-src 'self'",
    // wasm-unsafe-eval lets the RNNoise AudioWorklet compile its
    // WebAssembly (noise suppression). It permits WASM only - NOT JS
    // eval() - so script-src stays strict against injected scripts.
    "script-src 'self' 'wasm-unsafe-eval'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "media-src 'self' blob:",
    "connect-src 'self' wss: ws:",
    "worker-src 'self' blob:",
    "font-src 'self'",
    "base-uri 'self'",
    "form-action 'self'",
    `frame-ancestors ${FRAME_ANCESTORS || "'none'"}`,
    "object-src 'none'"
  ].join("; "));
  // Pages and the service worker must always come from the server -
  // a cached copy pins old asset versions and serves stale app code
  if (/^\/(s\/|host\/?$|admin\/?$|sw\.js$)|\.html$|^\/$/.test(req.path)) {
    res.setHeader("Cache-Control", "no-store");
  }
  next();
});

app.use("/api", api);

// The two panels are separate sessions with separate cookies, so the
// admin (fleet) panel and a host dashboard can be open side by side.
// Same shell, gated by the matching cookie; everything inside is
// API-gated too.
app.get(["/host", "/host/"], (req, res) => {
  if (!isAuthedRequest(req, "host")) return res.redirect("/host/login.html");
  res.sendFile(path.join(config.webDir, "host", "index.html"));
});
app.get(["/admin", "/admin/"], (req, res) => {
  if (!isAuthedRequest(req, "admin")) return res.redirect("/host/login.html");
  res.sendFile(path.join(config.webDir, "host", "index.html"));
});

// A one-time sign-in link from admin-login-link.js: redeemed here, it
// becomes an ordinary session for that account and sends them to the
// panel their role lives in. Used up on the first visit; a second
// visit, or a stale one, lands on the login page like anyone else.
app.get("/link/:token([A-Za-z0-9_-]{16,200})", async (req, res) => {
  const uid = await redeemLink(req.params.token).catch(() => null);
  const user = uid ? await findById(uid).catch(() => null) : null;
  if (!user) return res.redirect("/host/login.html");
  setAuthCookie(res, user);
  // ?embed=1: the page that framed this studio has a shell of its own,
  // so the studio's top bar (wordmark, who, log out) is dropped for the
  // session. A plain cookie the page script can read; it grants nothing.
  if (req.query.embed === "1") {
    res.append("Set-Cookie", "fs_embed=1; Path=/; Secure; SameSite=Lax; Max-Age=43200");
  }
  res.redirect(user.role === "admin" ? "/admin/" : "/host/");
});

app.get("/healthz", (req, res) => {
  res.json({ ok: true, uptime: Math.round(process.uptime()) });
});

// What is running, for whoever is looking after the box: a self-hoster's
// own uptime check, or an operator running several. Read once at start,
// from the package file, so it cannot drift from what was installed.
const VERSION = (() => {
  try {
    return JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8")).version || "unknown";
  } catch {
    return "unknown";
  }
})();
app.get("/version", (req, res) => {
  res.json({ name: "fossstudio", version: VERSION });
});

// The root goes to the dashboard: on the dedicated panel domains
// (admin.example.com / host.example.com, when configured) straight to
// that panel; anywhere else to the host side. Each shows its login when
// signed out. Guests never visit the root - they arrive on /s/<id>
// links - so nothing is lost by forwarding it.
app.get("/", (req, res) => {
  const name = (req.hostname || "").toLowerCase();
  const target = panelDomains("admin").has(name) ? "/admin/" : "/host/";
  res.redirect(target);
});

// Caddy asks here before fetching a certificate on demand: only the
// panel domains derived from DOMAIN (plus explicit ADMIN_DOMAIN /
// HOST_DOMAIN) are approved, so pointing a random name at this server
// can never mint a certificate. Same public posture as /healthz - the
// answer reveals nothing beyond names any visitor already sees.
app.get("/tls-allowed", (req, res) => {
  const d = String(req.query.domain || "").toLowerCase();
  const ok = panelDomains("admin").has(d) || panelDomains("host").has(d);
  res.status(ok ? 200 : 404).end();
});

// Session links guests receive: https://<domain>/s/<room-id>
app.get("/s/:roomId([a-zA-Z0-9_-]{4,32})", (req, res) => {
  res.sendFile(path.join(config.webDir, "session.html"));
});

// Big unchanging assets get real caching; pages stay fresh
for (const dir of ["assets", "fonts", "icons"]) {
  app.use(`/${dir}`, express.static(path.join(config.webDir, dir), { maxAge: "7d" }));
}
app.use(express.static(config.webDir, { index: false }));

app.use((req, res) => {
  res.status(404).sendFile(path.join(config.webDir, "404.html"), (err) => {
    if (err) res.status(404).send("Not found");
  });
});

const server = http.createServer(app);
// Session signaling is the one WebSocket endpoint; an upgrade asked for
// anywhere else is not ours.
const wssSignal = attachSignaling();
server.on("upgrade", (req, socket, head) => {
  const { pathname } = new URL(req.url, "http://localhost");
  if (pathname !== "/ws") return socket.destroy();
  wssSignal.handleUpgrade(req, socket, head, (ws) => wssSignal.emit("connection", ws, req));
});

await startMediasoup();
await initPush();
scheduleDailyBackups();

process.on("uncaughtException", (err) => {
  console.error("uncaught exception:", err.stack || err.message);
  // A process that limps on after an uncaught throw is in an unknown
  // state - a failed port bind used to leave a zombie server squatting
  // RAM forever. Dying cleanly lets Docker restart it fresh.
  process.exit(1);
});
process.on("unhandledRejection", (err) => {
  console.error("unhandled rejection:", err?.stack || String(err));
});

// Loopback by default: only the reverse proxy on this host talks to the
// app directly. BIND_HOST widens that for setups with no local proxy
// (e.g. a Tailscale address, or 0.0.0.0 behind a proxy in another
// container) - never expose the app port itself to the open internet.


server.listen(config.httpPort, "0.0.0.0", () => {
  console.log(`FOSS Studio listening on 0.0.0.0:${config.httpPort}`);
});

