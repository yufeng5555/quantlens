"""Email magic-link identity for QuantLens.

This is the first real account boundary in the product. It deliberately stores
**no passwords**: a sign-in request mints one short-lived single-use link, and
following that link establishes a session cookie. Nothing here can be replayed
from the database alone — the login token and the session identifier are both
held only as SHA-256 digests, so a leaked store yields no usable credential.

Boundaries this module keeps, in the same fail-closed spirit as the rest of the
control plane:

* **Opaque identity.** An account's storage identity is ``acct-<hex>``, never
  the address. Ownership columns, artifacts and manifests therefore carry no
  personal data, and the existing per-principal isolation applies unchanged.
* **Single use.** A login token is consumed inside one guarded transaction; a
  second follow of the same link cannot mint a second session.
* **No enumeration.** Requesting a link answers identically whether or not the
  address already has an account, and the request path never reveals account
  existence through timing-independent content.
* **No silent delivery.** If no email sender is configured the request fails
  closed with a typed refusal rather than pretending a link was sent.

The provider satisfies :class:`quantlens_api.auth.AuthProvider`, so installing
it is the only step that turns the deployment from local preview into an
authenticated one.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import secrets
import unicodedata
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Request, status

from .auth import Principal

logger = logging.getLogger("quantlens.api.magic_link")

MAGIC_LINK_MODE = "email-magic-link"

SESSION_COOKIE_NAME = "ql_session"

# A login link is a bearer credential in an inbox: minutes, not hours.
LOGIN_TOKEN_TTL = timedelta(minutes=15)
# A signed-in research session; sign-out and expiry both revoke it.
SESSION_TTL = timedelta(days=14)
# One address may hold only this many unconsumed live links at once, which
# bounds inbox flooding without telling the caller whether the account exists.
MAX_LIVE_TOKENS_PER_EMAIL = 3
# The per-address cap alone does not bound a public deployment: anyone may type
# any stranger's address, so an instance that mails on demand can be driven to
# flood inboxes it has no relationship with, burn the sending domain's
# reputation, and exhaust the provider quota. The whole instance is therefore
# bounded per rolling hour as well. Both caps answer with the same accepted
# body, so neither becomes an oracle.
MAX_SIGN_IN_EMAILS_PER_HOUR = 60
SIGN_IN_EMAIL_WINDOW = timedelta(hours=1)
# Registration is open, and every account carries a compute allowance on shared
# hardware. A bound on how many may exist keeps an open front door from also
# being an open compute door. Raising it is a deliberate operator decision.
MAX_ACCOUNTS = 200

REPORT_ROLES = ("novice", "expert")
DEFAULT_REPORT_ROLE = "novice"

# Deliberately conservative: a single address, no display name, no folding
# tricks, and a length bound well under the RFC maximum.
_EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


class MagicLinkError(ValueError):
    """A magic-link request or redemption violated the closed contract."""


def normalize_email(value: object) -> str:
    """Validate and canonicalize one address, or fail closed.

    Normalization is NFKC plus lowercasing so that visually identical
    addresses cannot create two accounts. The local part is otherwise left
    intact: QuantLens does not assume provider-specific aliasing rules.
    """
    if not isinstance(value, str):
        raise MagicLinkError("email must be a string")
    candidate = unicodedata.normalize("NFKC", value).strip().lower()
    if any(unicodedata.category(char).startswith("C") for char in candidate):
        raise MagicLinkError("email must not contain control characters")
    if len(candidate) > 254 or not _EMAIL_PATTERN.fullmatch(candidate):
        raise MagicLinkError("email must be one ordinary address")
    return candidate


def normalize_report_role(value: object) -> str:
    """Validate the report presentation role, or fail closed."""
    if value not in REPORT_ROLES:
        raise MagicLinkError(
            f"report_role must be one of {', '.join(REPORT_ROLES)}")
    assert isinstance(value, str)
    return value


def display_label_for(email: str) -> str:
    """A non-identifying label for the workspace chrome.

    The full address is never rendered in shared chrome; the local part is
    enough for a person to recognize their own workspace.
    """
    local_part = email.split("@", 1)[0]
    return local_part[:40] if local_part else "Research workspace"


def new_account_id() -> str:
    """An opaque, storage-safe account identity (also the tenant/user id)."""
    return f"acct-{secrets.token_hex(16)}"


def mint_secret() -> str:
    """One URL-safe bearer secret with 256 bits of entropy."""
    return secrets.token_urlsafe(32)


def digest(secret: str) -> str:
    """The at-rest form of a bearer secret. Only digests are ever stored."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


@dataclass(frozen=True)
class AccountSession:
    """A redeemed session: the account it belongs to and when it expires."""

    account_id: str
    email: str
    display_label: str
    report_role: str
    expires_at: str


def principal_for(session: AccountSession, mode: str = MAGIC_LINK_MODE) -> Principal:
    """Project a redeemed session into the provider-neutral principal.

    The account owns exactly one personal workspace, so tenant and user are the
    same opaque id — the shape every ``*_for_principal`` accessor already
    expects.

    ``mode`` names how this deployment establishes accounts. A session cookie is
    a session cookie however it was obtained, but the principal must not claim a
    sign-in method the deployment does not offer: the workspace page shows this
    value to the person it describes.
    """
    return Principal(
        tenant_id=session.account_id,
        user_id=session.account_id,
        roles=frozenset({"owner"}),
        auth_mode=mode,
        display_label=session.display_label,
        authenticated=True,
        security_boundary=True,
    )


def cookie_is_secure(request: Request) -> bool:
    """Whether the session cookie may carry the Secure attribute.

    Loopback development is plain HTTP, so demanding Secure there would drop
    the cookie entirely. Anything that is not loopback must be HTTPS before it
    receives a session.

    A deployment sets ``QL_COOKIE_SECURE`` and stops depending on header
    plumbing entirely. This matters because the browser never reaches this API
    directly: it talks to the web app, which proxies here over loopback, so
    whether ``x-forwarded-proto`` survives that hop is a property of the proxy
    rather than of the deployment. An operator who knows the edge terminates
    TLS states it once, and a public session cookie can never silently be
    issued without Secure because a header went missing.
    """
    declared = (os.environ.get("QL_COOKIE_SECURE") or "").strip().lower()
    if declared in ("1", "true", "yes"):
        return True
    forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",")[0]
    scheme = (forwarded_proto or request.url.scheme or "").strip().lower()
    return scheme == "https"


class MagicLinkAuthProvider:
    """Resolve the session cookie into a principal, or fail closed.

    The provider performs no database writes: redemption and revocation are
    explicit route actions, so an ordinary read of a private route can never
    extend or mint a session.

    It serves every deployment whose accounts are session-cookie backed,
    whichever way the address was proved — an emailed link or an external
    identity provider. ``mode`` names that way, and travels into the principal
    so no surface can claim a sign-in method the deployment does not offer.
    """

    mode = MAGIC_LINK_MODE

    def __init__(self, resolve_session, mode: str = MAGIC_LINK_MODE) -> None:
        # Injected so the identity contract stays independent of the storage
        # module and can be exercised without a database in unit tests.
        self._resolve_session = resolve_session
        self.mode = mode

    def authenticate(self, request: Request) -> Principal:
        raw = request.cookies.get(SESSION_COOKIE_NAME)
        if not raw:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "code": "AUTH_SESSION_REQUIRED",
                    "message": "Sign in to open this workspace.",
                },
            )
        session = self._resolve_session(digest(raw), utc_now())
        if session is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "code": "AUTH_SESSION_INVALID",
                    "message": "This session has expired. Sign in again.",
                },
            )
        return principal_for(session, self.mode)


def _positive_int_env(name: str, default: int) -> int:
    """One operator-tunable bound. A malformed value keeps the safe default."""
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        logger.warning("ignoring malformed %s; keeping default", name)
        return default
    if value <= 0:
        logger.warning("ignoring non-positive %s; keeping default", name)
        return default
    return value


def sign_in_emails_per_hour() -> int:
    return _positive_int_env("QL_AUTH_EMAIL_HOURLY_CAP", MAX_SIGN_IN_EMAILS_PER_HOUR)


def max_accounts() -> int:
    return _positive_int_env("QL_MAX_ACCOUNTS", MAX_ACCOUNTS)


def email_sender_configured() -> bool:
    """Whether this deployment can actually deliver a link."""
    mode = (os.environ.get("QL_AUTH_EMAIL_MODE") or "").strip().lower()
    if mode == "console":
        return True
    return bool((os.environ.get("QL_RESEND_API_KEY") or "").strip())


def sign_in_url(web_origin: str, token: str) -> str:
    """The link a recipient follows.

    It points at the WEB app, not the API: a person clicking a link in their
    inbox must land on a page, and the redemption call is made from there.
    """
    return f"{web_origin.rstrip('/')}/signin/callback?token={token}"


def _public_web_origin(request) -> str:
    """Where the recipient's browser should land.

    The operator-configured origin always wins. A caller-supplied Host header
    is never trusted for a configured deployment, because that would let a
    request point its own sign-in link at an attacker's origin. Falling back
    to the request origin only helps loopback development, where the API and
    the browser share a machine.
    """
    configured = (os.environ.get("QL_PUBLIC_WEB_ORIGIN") or "").strip()
    if configured:
        return configured
    return str(request.base_url).rstrip("/")


def deliver_sign_in_link(email: str, token: str, request) -> None:
    """Send one sign-in link, or raise if this deployment cannot.

    ``console`` mode is for loopback development: the link is written to the
    API log so a developer can follow it without an email provider. It is
    refused whenever the request did not come from loopback, so a deployed
    instance can never quietly print credentials instead of mailing them.
    """
    mode = (os.environ.get("QL_AUTH_EMAIL_MODE") or "").strip().lower()
    url = sign_in_url(_public_web_origin(request), token)
    if mode == "console":
        client = request.client
        host = (client.host if client else "") or ""
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise MagicLinkError(
                "console sign-in delivery is available only on loopback")
        logger.warning(
            "DEV SIGN-IN LINK for %s: %s", email, url)
        return
    api_key = (os.environ.get("QL_RESEND_API_KEY") or "").strip()
    if not api_key:
        raise MagicLinkError("no sign-in email sender is configured")
    _send_via_resend(api_key, email, url)


def _send_via_resend(api_key: str, email: str, url: str) -> None:
    """Deliver through Resend. The token appears only in the message body."""
    sender = (os.environ.get("QL_AUTH_EMAIL_FROM")
              or "QuantLens <onboarding@resend.dev>").strip()
    payload = json.dumps({
        "from": sender,
        "to": [email],
        "subject": "Your QuantLens sign-in link",
        "text": (
            "Use this link to sign in to QuantLens:\n\n"
            f"{url}\n\n"
            "It expires in 15 minutes and works once. "
            "If you did not request it, you can ignore this message."
        ),
    }).encode("utf-8")
    api_request = urllib.request.Request(
        "https://api.resend.com/emails",
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(api_request, timeout=15) as response:
            if int(response.status) >= 300:
                raise MagicLinkError("the email provider refused the message")
    except urllib.error.URLError as error:
        # The provider's own text may quote the address; keep it out of logs.
        raise MagicLinkError("the email provider could not be reached") from error


__all__ = [
    "AccountSession",
    "DEFAULT_REPORT_ROLE",
    "deliver_sign_in_link",
    "LOGIN_TOKEN_TTL",
    "MAGIC_LINK_MODE",
    "MAX_ACCOUNTS",
    "MAX_LIVE_TOKENS_PER_EMAIL",
    "MAX_SIGN_IN_EMAILS_PER_HOUR",
    "SIGN_IN_EMAIL_WINDOW",
    "max_accounts",
    "sign_in_emails_per_hour",
    "MagicLinkAuthProvider",
    "MagicLinkError",
    "REPORT_ROLES",
    "SESSION_COOKIE_NAME",
    "SESSION_TTL",
    "cookie_is_secure",
    "digest",
    "display_label_for",
    "email_sender_configured",
    "mint_secret",
    "new_account_id",
    "normalize_email",
    "normalize_report_role",
    "principal_for",
    "sign_in_url",
    "utc_now",
]
