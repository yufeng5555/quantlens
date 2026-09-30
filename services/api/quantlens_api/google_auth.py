"""Google sign-in for QuantLens.

The second way to prove control of an email address, and the one a deployment
uses when it has no domain of its own to send mail from. It establishes exactly
the same thing the emailed link establishes — "this person controls this
address" — and hands off to the same account and session machinery, so an
account reached either way is one account with one workspace.

What this module deliberately does NOT do:

* **No password, ever.** Google performs the authentication; QuantLens receives
  an address and nothing else it could leak.
* **No JWT parsing or signature verification by hand.** The authorization code
  is exchanged over TLS directly with Google's token endpoint, and the address
  is then read from Google's userinfo endpoint over that same authenticated
  channel. There is no attacker-supplied token to validate, so there is no
  hand-rolled crypto to get wrong.
* **No unverified address.** Google reports whether it has verified the
  address; an unverified one is refused rather than trusted, because otherwise
  a Google account could claim an address it does not own.

The defences on the way back are three, and they answer three different
attacks:

* **A single-use state row.** Stops a state being replayed.
* **A matching HttpOnly cookie.** The row alone would not stop an attacker who
  starts a flow and walks a victim through finishing it; the cookie binds the
  completion to the browser that began it.
* **PKCE.** The first two together still prove only that this browser started
  *a* flow — not that it started *the* flow the returned code belongs to. A
  refused callback leaves its authorization code unspent, alive, and recorded
  in browser history and access logs, so without PKCE somebody else could
  redeem that code inside their own valid flow and be handed a session in the
  victim's workspace. The verifier never leaves this server, so Google itself
  refuses the mismatch.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import timedelta

from .magic_link import (
    MagicLinkError,
    digest,
    mint_secret,
    normalize_email,
    utc_now,
)

logger = logging.getLogger("quantlens.api.google_auth")

GOOGLE_MODE = "google"

AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
USERINFO_ENDPOINT = "https://openidconnect.googleapis.com/v1/userinfo"

# Only what identifies the person. No Gmail, no Drive, no calendar — which is
# also why this client needs no Google verification review.
SCOPES = "openid email"

# The window between leaving for Google and coming back. Long enough for a
# password and a second factor, short enough that an abandoned state is not a
# standing invitation.
STATE_TTL = timedelta(minutes=15)
STATE_COOKIE_NAME = "ql_oauth_state"

_TOKEN_TIMEOUT_SECONDS = 15

# How many sign-ins may be part-way through at once, across the whole instance.
# This is a table-size backstop, not a security control: starting a flow costs
# an anonymous caller nothing, so the table must not be unbounded. It is set far
# above what a cohort produces, and every refusal now settles its own row
# immediately, so ordinary abandoned attempts do not accumulate against it.
# Sharing the sign-in email cap here — as an earlier version did — would have
# let sixty anonymous requests close the only front door for everyone.
MAX_IN_FLIGHT_SIGN_INS = 500


def max_in_flight_sign_ins() -> int:
    raw = (os.environ.get("QL_MAX_IN_FLIGHT_SIGN_INS") or "").strip()
    if not raw:
        return MAX_IN_FLIGHT_SIGN_INS
    try:
        value = int(raw)
    except ValueError:
        logger.warning("ignoring malformed QL_MAX_IN_FLIGHT_SIGN_INS")
        return MAX_IN_FLIGHT_SIGN_INS
    return value if value > 0 else MAX_IN_FLIGHT_SIGN_INS


class GoogleAuthError(MagicLinkError):
    """A Google sign-in attempt violated the closed contract.

    Subclasses the identity module's error so a route may treat every
    "this sign-in cannot proceed" case with one handler.
    """


@dataclass(frozen=True)
class GoogleIdentity:
    """What Google told us, reduced to the only fact QuantLens stores."""

    email: str


def client_id() -> str:
    return (os.environ.get("QL_GOOGLE_CLIENT_ID") or "").strip()


def _client_secret() -> str:
    return (os.environ.get("QL_GOOGLE_CLIENT_SECRET") or "").strip()


def google_sign_in_configured() -> bool:
    """Whether this deployment can actually complete a Google sign-in."""
    return bool(client_id() and _client_secret())


def redirect_uri() -> str:
    """Where Google returns the browser.

    Derived from the deployment's declared origin rather than from the incoming
    request, for the same reason the emailed link is: a caller-supplied Host
    must never be able to point an identity flow at somebody else's origin.
    This value has to match a redirect URI registered on the Google client
    exactly, character for character.
    """
    origin = (os.environ.get("QL_PUBLIC_WEB_ORIGIN") or "").strip().rstrip("/")
    if not origin:
        raise GoogleAuthError("QL_PUBLIC_WEB_ORIGIN is not configured")
    return f"{origin}/api/ql/auth/google/callback"


def new_code_verifier() -> str:
    """One PKCE verifier: high-entropy, server-held, never sent to the browser."""
    return secrets.token_urlsafe(64)


def code_challenge_for(verifier: str) -> str:
    """The S256 challenge Google stores against the code it issues."""
    hashed = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(hashed).decode("ascii").rstrip("=")


def authorization_url(state: str, code_verifier: str) -> str:
    """The URL the browser is sent to in order to choose a Google account.

    Carries a PKCE challenge. Without it, ``state`` proves only that the
    browser started *a* flow, not that it started *the* flow the returned code
    belongs to — so an unspent code lifted from someone's browser history or
    from an access log could be redeemed inside an attacker's own flow, and the
    attacker would land in that person's workspace. With it, Google itself
    refuses any code whose verifier does not hash to the challenge it was
    issued under, and the verifier never leaves this server.
    """
    if not google_sign_in_configured():
        raise GoogleAuthError("Google sign-in is not configured")
    query = urllib.parse.urlencode({
        "client_id": client_id(),
        "redirect_uri": redirect_uri(),
        "response_type": "code",
        "scope": SCOPES,
        "state": state,
        "code_challenge": code_challenge_for(code_verifier),
        "code_challenge_method": "S256",
        # Ask for an account choice every time rather than silently reusing
        # whichever Google session the browser happens to hold. On a shared or
        # lab machine that difference is the whole point.
        "prompt": "select_account",
    })
    return f"{AUTHORIZATION_ENDPOINT}?{query}"


def _post_form(url: str, fields: dict[str, str]) -> dict:
    body = urllib.parse.urlencode(fields).encode("ascii")
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(request, timeout=_TOKEN_TIMEOUT_SECONDS) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as error:
        # Google's body can echo the client secret back in an error; keep the
        # provider's text out of logs and responses entirely.
        raise GoogleAuthError("the identity provider could not be reached") from error
    except (ValueError, UnicodeDecodeError) as error:
        raise GoogleAuthError("the identity provider returned an unreadable response") from error


def _get_json(url: str, access_token: str) -> dict:
    request = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {access_token}"})
    try:
        with urllib.request.urlopen(request, timeout=_TOKEN_TIMEOUT_SECONDS) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as error:
        raise GoogleAuthError("the identity provider could not be reached") from error
    except (ValueError, UnicodeDecodeError) as error:
        raise GoogleAuthError("the identity provider returned an unreadable response") from error


def exchange_code_for_identity(code: str, code_verifier: str) -> GoogleIdentity:
    """Turn one authorization code into a proven address, or fail closed.

    The code is exchanged over TLS with Google directly, using the client
    secret. Nothing in this path parses a token the browser supplied, so a
    forged token is not a thing an attacker can present here.

    ``code_verifier`` is the PKCE half held only by the flow that asked for
    this code. Google refuses the exchange when it does not hash to the
    challenge the code was issued under, which is what stops a code taken from
    one person's flow being redeemed inside another person's.
    """
    if not isinstance(code, str) or not code.strip():
        raise GoogleAuthError("no authorization code was provided")
    if not isinstance(code_verifier, str) or not code_verifier.strip():
        raise GoogleAuthError("no PKCE verifier accompanied this exchange")
    if not google_sign_in_configured():
        raise GoogleAuthError("Google sign-in is not configured")

    tokens = _post_form(TOKEN_ENDPOINT, {
        "code": code,
        "client_id": client_id(),
        "client_secret": _client_secret(),
        "redirect_uri": redirect_uri(),
        "grant_type": "authorization_code",
        "code_verifier": code_verifier,
    })
    access_token = tokens.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise GoogleAuthError("the identity provider returned no access token")

    profile = _get_json(USERINFO_ENDPOINT, access_token)

    # Google states whether it has verified the address. An unverified one is
    # refused: without that check a Google account could assert an address it
    # does not control, and QuantLens keys workspaces on the address.
    if profile.get("email_verified") not in (True, "true"):
        raise GoogleAuthError("the identity provider has not verified this address")
    try:
        email = normalize_email(profile.get("email"))
    except MagicLinkError as error:
        raise GoogleAuthError("the identity provider returned no usable address") from error
    return GoogleIdentity(email=email)


def new_state() -> str:
    """One single-use, unguessable value tying a start to its callback."""
    return mint_secret()


def state_digest(state: str) -> str:
    return digest(state)


def state_expires_at() -> str:
    return (utc_now() + STATE_TTL).isoformat()


__all__ = [
    "AUTHORIZATION_ENDPOINT",
    "GOOGLE_MODE",
    "GoogleAuthError",
    "GoogleIdentity",
    "MAX_IN_FLIGHT_SIGN_INS",
    "SCOPES",
    "STATE_COOKIE_NAME",
    "STATE_TTL",
    "TOKEN_ENDPOINT",
    "USERINFO_ENDPOINT",
    "authorization_url",
    "client_id",
    "code_challenge_for",
    "exchange_code_for_identity",
    "google_sign_in_configured",
    "max_in_flight_sign_ins",
    "new_code_verifier",
    "new_state",
    "redirect_uri",
    "state_digest",
    "state_expires_at",
]
