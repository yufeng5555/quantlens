/** @type {import('next').NextConfig} */
const API_ORIGIN = process.env.QL_API_ORIGIN ?? "http://127.0.0.1:8000";

function assertLoopbackApiOrigin(rawOrigin) {
  let origin;
  try {
    origin = new URL(rawOrigin);
  } catch {
    throw new Error("QL_API_ORIGIN must be a valid loopback HTTP URL.");
  }

  const isLoopbackHost =
    origin.hostname === "127.0.0.1" ||
    origin.hostname === "localhost" ||
    origin.hostname === "[::1]";
  if (origin.protocol !== "http:" || !isLoopbackHost || origin.username || origin.password) {
    throw new Error(
      "QL_API_ORIGIN must use plain HTTP on localhost, 127.0.0.1, or [::1] for local preview.",
    );
  }

  return origin.origin;
}

const LOOPBACK_API_ORIGIN = assertLoopbackApiOrigin(API_ORIGIN);

// The CSV import limit the API enforces and the Data page advertises. Next truncates a
// proxied request body at its own ceiling -- 10MB by default -- while still forwarding the
// caller's original Content-Length, so the API sits waiting for bytes that never arrive.
// Measured: an 11MB upload hung for the proxy's full 30s timeout and then returned a bare
// non-JSON 500, while the page promised 12MB. Tying the two numbers together here is what
// keeps that promise honest; they must not drift apart.
const MAX_UPLOAD_BYTES = 12 * 1024 * 1024;

const nextConfig = {
  // Isolated instances (Playwright) get their own dist dir so the one-dev-server-per-
  // directory lock never collides with a normal `npm run dev`.
  distDir: process.env.QL_DIST_DIR ?? ".next",
  experimental: {
    proxyClientMaxBodySize: MAX_UPLOAD_BYTES,
  },
  // This build is presented to non-developers; the floating dev indicator reads as
  // debug chrome, so keep it off in this local presentation build.
  devIndicators: false,
  async headers() {
    // fly.toml's force_https redirects http to https, which means the FIRST request of
    // every visit still leaves the browser in plaintext and can be answered by anyone on
    // the path -- including the redirect itself. HSTS is what removes that request: after
    // one https response the browser upgrades on its own, without asking the network.
    //
    // Deliberately only this header. An audit examined CSP and X-Frame-Options here and
    // found no threat they close for this app: the session cookie is SameSite=lax so a
    // framed page renders signed out, nothing in apps/web uses dangerouslySetInnerHTML,
    // srcDoc or innerHTML, the report templates autoescape, and the referrer policy
    // already defaults to strict-origin-when-cross-origin. Shipping headers that answer
    // no threat is how a security posture becomes decoration.
    //
    // No `preload`: that is a submission to a browser-vendor list and is painful to
    // reverse. max-age is one year, the usual floor for HSTS to be worth having.
    //
    // Localhost is exempt: browsers ignore HSTS there, but emitting it from a dev server
    // would still be stating something untrue about how that origin is served.
    if (process.env.NODE_ENV !== "production") return [];
    return [{
      source: "/:path*",
      headers: [{
        key: "Strict-Transport-Security",
        value: "max-age=31536000; includeSubDomains",
      }],
    }];
  },
  async rewrites() {
    // Local-only proxy to the FastAPI control plane; keeps the browser same-origin.
    // proxy.ts rejects non-loopback request authorities before this rewrite runs.
    return [{ source: "/api/ql/:path*", destination: `${LOOPBACK_API_ORIGIN}/:path*` }];
  },
};

export default nextConfig;
