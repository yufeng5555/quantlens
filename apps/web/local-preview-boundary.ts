const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

function unquote(value: string): string {
  const trimmed = value.trim();
  if (trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length >= 2) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function hostnameFromAuthority(rawAuthority: string): string | null {
  const authority = unquote(rawAuthority).toLowerCase();
  if (!authority || authority.includes("/") || authority.includes("@")) {
    return null;
  }

  if (authority.startsWith("[")) {
    const closingBracket = authority.indexOf("]");
    if (closingBracket < 0) return null;
    const remainder = authority.slice(closingBracket + 1);
    if (remainder && !/^:\d+$/.test(remainder)) return null;
    return authority.slice(1, closingBracket);
  }

  const parts = authority.split(":");
  if (parts.length > 2 || (parts.length === 2 && !/^\d+$/.test(parts[1]))) {
    return null;
  }
  return parts[0].replace(/\.$/, "");
}

function isLoopbackAuthority(value: string): boolean {
  const hostname = hostnameFromAuthority(value);
  return hostname !== null && LOOPBACK_HOSTS.has(hostname);
}

function allCommaSeparatedValuesSatisfy(
  rawValue: string | null,
  validator: (value: string) => boolean,
): boolean {
  if (rawValue === null) return true;
  const values = rawValue.split(",").map((value) => value.trim());
  return values.length > 0 && values.every((value) => value.length > 0 && validator(value));
}

function isLoopbackAddress(rawAddress: string): boolean {
  const address = unquote(rawAddress).toLowerCase();
  if (address === "127.0.0.1" || address === "::1" || address === "[::1]") {
    return true;
  }
  if (address.startsWith("[::1]:") && /^\[::1\]:\d+$/.test(address)) {
    return true;
  }
  return /^127\.0\.0\.1:\d+$/.test(address);
}

function forwardedHeaderIsLoopback(rawForwarded: string | null): boolean {
  if (rawForwarded === null) return true;
  const elements = rawForwarded.split(",").map((element) => element.trim());
  if (elements.length === 0 || elements.some((element) => !element)) return false;

  return elements.every((element) => {
    const parameters = new Map<string, string>();
    for (const rawParameter of element.split(";")) {
      const separator = rawParameter.indexOf("=");
      if (separator <= 0) return false;
      parameters.set(
        rawParameter.slice(0, separator).trim().toLowerCase(),
        rawParameter.slice(separator + 1).trim(),
      );
    }

    const host = parameters.get("host");
    const forwardedFor = parameters.get("for");
    return Boolean(
      host &&
        forwardedFor &&
        isLoopbackAuthority(host) &&
        isLoopbackAddress(forwardedFor),
    );
  });
}

export function isLocalPreviewRequest(headers: Headers): boolean {
  const host = headers.get("host");
  if (!host || !isLoopbackAuthority(host)) return false;

  if (
    !allCommaSeparatedValuesSatisfy(
      headers.get("x-forwarded-host"),
      isLoopbackAuthority,
    ) ||
    !allCommaSeparatedValuesSatisfy(headers.get("x-forwarded-for"), isLoopbackAddress) ||
    !allCommaSeparatedValuesSatisfy(headers.get("x-real-ip"), isLoopbackAddress) ||
    !forwardedHeaderIsLoopback(headers.get("forwarded"))
  ) {
    return false;
  }

  return true;
}

/**
 * The single deployment shape allowed to serve anyone but this device.
 *
 * The loopback-only boundary above exists because a local preview has no
 * authentication at all: whoever reaches it receives the local principal's
 * workspace. That premise stops holding only when the deployment establishes a
 * real account boundary, so the network boundary opens on exactly that
 * condition and on nothing else.
 *
 * Three facts must all hold, or the answer stays "closed":
 *
 * 1. ``QL_AUTH_MODE`` selects the account boundary. An unauthenticated
 *    deployment is never reachable, whatever else is configured.
 * 2. ``QL_PUBLIC_WEB_ORIGIN`` names one exact https origin. This is the same
 *    value the API stamps into emailed sign-in links, so the host that serves
 *    the app and the host those links point at cannot drift apart.
 * 3. The origin is https. A session cookie is marked Secure only over TLS;
 *    serving the account boundary in the clear would hand out a bearer
 *    credential that travels unencrypted.
 *
 * Absent or malformed configuration returns null, which leaves the deployment
 * loopback-only rather than open.
 */
// Every mode that establishes a real account boundary. They differ only in how
// an address is proved — an emailed link, or Google — and not at all in what
// the network boundary may then serve.
const ACCOUNT_BOUNDARY_MODES = new Set(["email-magic-link", "google"]);

function deployedOrigin(): URL | null {
  const declared = (process.env.QL_PUBLIC_WEB_ORIGIN ?? "").trim();
  const mode = (process.env.QL_AUTH_MODE ?? "").trim().toLowerCase();
  if (!declared || !ACCOUNT_BOUNDARY_MODES.has(mode)) return null;

  let origin: URL;
  try {
    origin = new URL(declared);
  } catch {
    return null;
  }
  if (origin.protocol !== "https:" || origin.username || origin.password) return null;
  // A loopback "public" origin is a misconfiguration, not a deployment.
  if (LOOPBACK_HOSTS.has(origin.hostname)) return null;
  return origin;
}

function authorityIsDeployedHost(value: string, origin: URL): boolean {
  const hostname = hostnameFromAuthority(value);
  return hostname !== null && hostname === origin.hostname;
}

/**
 * Whether this request may be served at all. Loopback keeps its existing
 * developer flows untouched; everything else must match the one declared
 * deployment origin and arrive over TLS.
 */
export function isServableRequest(headers: Headers): boolean {
  const origin = deployedOrigin();

  // A deployed instance serves its declared origin and nothing else — not even
  // a request claiming a loopback Host. Today such a request is already refused
  // because the edge stamps a non-loopback X-Forwarded-For, but that makes the
  // boundary depend on a platform behaviour nothing in this repository pins.
  // Deciding it here costs nothing and removes that dependency: a deployed
  // build has no use for the loopback branch, because the only process that
  // talks to the web app is the edge proxy.
  if (origin === null) return isLocalPreviewRequest(headers);

  const host = headers.get("host");
  if (!host || !authorityIsDeployedHost(host, origin)) return false;

  // A proxy may restate the host; if it does, it must restate the same one.
  const forwardedHost = headers.get("x-forwarded-host");
  if (
    forwardedHost !== null
    && !allCommaSeparatedValuesSatisfy(
      forwardedHost, (value) => authorityIsDeployedHost(value, origin))
  ) {
    return false;
  }

  // The terminating proxy must report TLS. Without this the app would serve
  // the account boundary over a plaintext hop.
  const proto = (headers.get("x-forwarded-proto") ?? "").split(",")[0].trim().toLowerCase();
  return proto === "https";
}
