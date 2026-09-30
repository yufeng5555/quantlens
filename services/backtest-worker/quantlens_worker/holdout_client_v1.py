"""Worker-side FINAL_EVALUATOR client for the external holdout authority (C3).

Signs the closed client-request envelope, drives the frozen one-use access
protocol (lease -> consume -> complete -> retrieve audit) over an injected
loopback transport, and fail-closed verifies every signed response: the
hash-pinned authority trust bundle is proved before any key is read, the
neutral wrapper law is applied, the transport status/cache headers are
cross-checked, the request identity is echo-bound, and the authority Ed25519
signature is verified under its own domain.  Any embedded terminal audit is
independently signature-verified before it is returned.

Released plaintext is handed to the caller's evaluator exactly once and is
never stored on the client, logged, or included in the driver's return value.

Dormant Stop C module: no active runner, API, queue, report or web surface
imports it; execution wiring arrives only through a later reviewed stop.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, NamedTuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from quantlens_schema.final_holdout_access_protocol_v1 import (
    FINAL_EVALUATOR_ROLE,
    FINAL_HOLDOUT_ACCESS_AUDIT_DOMAIN_V1,
    FINAL_HOLDOUT_ACCESS_PROTOCOL,
    FINAL_HOLDOUT_AUDIT_RETRIEVAL_BODY_VERSION_V1,
    FINAL_HOLDOUT_AUDIT_RETRIEVE_PATH_TEMPLATE_V1,
    FINAL_HOLDOUT_CLIENT_REQUEST_DOMAIN_V1,
    FINAL_HOLDOUT_CLIENT_REQUEST_VERSION_V1,
    FINAL_HOLDOUT_COMPLETE_PATH_TEMPLATE_V1,
    FINAL_HOLDOUT_COMPLETION_REQUEST_BODY_VERSION_V1,
    FINAL_HOLDOUT_CONSUME_PATH_TEMPLATE_V1,
    FINAL_HOLDOUT_CONSUME_REQUEST_BODY_VERSION_V1,
    FINAL_HOLDOUT_LEASE_PATH_V1,
    FINAL_HOLDOUT_LEASE_REQUEST_BODY_VERSION_V1,
    FINAL_HOLDOUT_SERVICE_RESPONSE_DOMAIN_V1,
    MAX_CLIENT_REQUEST_BODY_BYTES,
    canonical_final_holdout_audit_retrieval_body_bytes,
    canonical_final_holdout_completion_request_body_bytes,
    canonical_final_holdout_consume_request_body_bytes,
    canonical_final_holdout_lease_request_body_bytes,
    canonical_json_bytes,
    canonical_unsigned_final_holdout_access_audit_bytes,
    canonical_unsigned_final_holdout_client_request_bytes,
    canonical_unsigned_final_holdout_service_response_bytes,
    final_holdout_authority_trust_bundle_hash,
    validate_final_holdout_authority_trust_bundle_v1,
    validate_final_holdout_client_request_v1,
    validate_final_holdout_response_wrapper_v1,
)

_RELEASE_ID = "quantlens-financial-v3"
_PREFIXED_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_LOOPBACK_BASE_URL_RE = re.compile(r"^http://(?:127\.0\.0\.1|\[::1\]):\d{1,5}$")
_COMPLETION_OUTCOMES = ("evaluation_succeeded", "evaluation_failed")


class HoldoutClientError(ValueError):
    """One access-protocol step failed closed; no bytes are trusted."""

    def __init__(self, message: str, *, code: str | None = None,
                 status_code: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code


class HoldoutLeaseDenied(HoldoutClientError):
    """The authority durably denied the lease and returned a signed audit."""

    def __init__(self, message: str, *, code: str, status_code: int,
                 terminal_audit: Mapping[str, Any]) -> None:
        super().__init__(message, code=code, status_code=status_code)
        self.terminal_audit = dict(terminal_audit)


class HoldoutAuditPending(HoldoutClientError):
    """The lease is not terminal yet; no audit exists to retrieve."""


class TransportResponse(NamedTuple):
    status: int
    headers: Mapping[str, str]
    body: bytes


def _fail(detail: str, *, code: str | None = None,
          status_code: int | None = None) -> None:
    raise HoldoutClientError(detail, code=code, status_code=status_code)


def _require(condition: bool, detail: str) -> None:
    if not condition:
        _fail(detail)


def _fresh(value: Any, label: str) -> Any:
    try:
        return json.loads(canonical_json_bytes(value).decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - fail closed on any canonical error
        raise HoldoutClientError(
            f"{label} is not canonical JSON") from exc


def loopback_urllib_transport_v1(
    base_url: str, *, timeout_seconds: float = 5.0,
) -> Callable[[str, bytes], TransportResponse]:
    """Build a stdlib POST transport pinned to one loopback origin.

    The opener is constructed with an empty proxy handler so a hostile
    ``*_proxy`` environment variable can never re-route authority traffic off
    the loopback interface.
    """
    _require(
        isinstance(base_url, str)
        and _LOOPBACK_BASE_URL_RE.fullmatch(base_url) is not None,
        "the authority base URL must be an exact loopback origin",
    )
    _require(
        isinstance(timeout_seconds, (int, float))
        and not isinstance(timeout_seconds, bool) and timeout_seconds > 0,
        "the transport timeout must be a positive number",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def transport(path: str, payload: bytes) -> TransportResponse:
        request = urllib.request.Request(
            base_url + path, data=payload, method="POST",
            headers={"Content-Type": "application/json"})
        try:
            with opener.open(request, timeout=timeout_seconds) as response:
                return TransportResponse(
                    status=int(response.status),
                    headers={key.lower(): value
                             for key, value in response.headers.items()},
                    body=response.read(),
                )
        except urllib.error.HTTPError as error:
            body = error.read()
            return TransportResponse(
                status=int(error.code),
                headers={key.lower(): value
                         for key, value in error.headers.items()}
                if error.headers else {},
                body=body,
            )
        except urllib.error.URLError as error:
            raise HoldoutClientError(
                "the final-holdout authority transport failed") from error

    return transport


class FinalHoldoutClientV1:
    """One evaluator identity speaking the frozen one-use access protocol."""

    def __init__(
        self,
        *,
        authority_id: str,
        caller_key_id: str,
        signer: Callable[[bytes], bytes],
        trust_bundle: Mapping[str, Any],
        expected_trust_bundle_sha256: str,
        transport: Callable[[str, bytes], TransportResponse],
        now: Callable[[], datetime],
        request_id_factory: Callable[[], str] | None = None,
        nonce_factory: Callable[[], str] | None = None,
        max_response_skew_seconds: int | None = None,
    ) -> None:
        _require(isinstance(authority_id, str) and bool(authority_id),
                 "authority_id must be a non-empty identity")
        _require(isinstance(caller_key_id, str) and bool(caller_key_id),
                 "caller_key_id must be a non-empty identity")
        _require(callable(signer), "signer must be callable")
        _require(callable(transport), "transport must be callable")
        _require(callable(now), "now must be callable")
        # Trust pin FIRST: the expected digest is shape-checked and matched
        # before the bundle is validated or any key is read.
        _require(
            isinstance(expected_trust_bundle_sha256, str)
            and _PREFIXED_SHA256_RE.fullmatch(
                expected_trust_bundle_sha256) is not None,
            "the expected trust bundle hash must be sha256: plus 64 lowercase "
            "hex; a bare or uppercase digest is never normalized",
        )
        try:
            actual = final_holdout_authority_trust_bundle_hash(trust_bundle)
        except Exception as exc:  # noqa: BLE001 - closed protocol failure
            raise HoldoutClientError(
                "the authority trust bundle failed its closed shape law"
            ) from exc
        _require(actual == expected_trust_bundle_sha256,
                 "the authority trust bundle does not match its pinned digest")
        try:
            bundle = validate_final_holdout_authority_trust_bundle_v1(
                trust_bundle)
        except Exception as exc:  # noqa: BLE001
            raise HoldoutClientError(
                "the authority trust bundle failed its closed shape law"
            ) from exc
        _require(bundle["authority_id"] == authority_id,
                 "the trust bundle serves a different authority")
        if max_response_skew_seconds is not None:
            _require(
                isinstance(max_response_skew_seconds, int)
                and not isinstance(max_response_skew_seconds, bool)
                and max_response_skew_seconds > 0,
                "max_response_skew_seconds must be a positive integer",
            )
        self._authority_id = authority_id
        self._caller_key_id = caller_key_id
        self._signer = signer
        self._bundle = bundle
        self._transport = transport
        self._now = now
        self._request_id_factory = request_id_factory or (
            lambda: "fha-req-" + secrets.token_hex(16))
        self._nonce_factory = nonce_factory or (lambda: secrets.token_hex(16))
        self._max_skew = max_response_skew_seconds

    # ------------------------------------------------------------- internals

    def _trusted_now(self) -> datetime:
        value = self._now()
        _require(
            isinstance(value, datetime) and value.tzinfo is not None
            and value.utcoffset() == timezone.utc.utcoffset(None)
            and value.microsecond == 0,
            "the client clock must return whole-second aware UTC time",
        )
        return value

    def _signed_request(self, *, path: str, body_bytes: bytes,
                        now: datetime) -> dict[str, Any]:
        _require(len(body_bytes) <= MAX_CLIENT_REQUEST_BODY_BYTES,
                 "the request body exceeds the frozen size cap")
        request_id = self._request_id_factory()
        nonce = self._nonce_factory()
        request = {
            "request_version": FINAL_HOLDOUT_CLIENT_REQUEST_VERSION_V1,
            "request_id": request_id,
            "authority_id": self._authority_id,
            "caller_role": FINAL_EVALUATOR_ROLE,
            "caller_key_id": self._caller_key_id,
            "method": "POST",
            "path": path,
            "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "nonce": nonce,
            "body_sha256": "sha256:" + hashlib.sha256(body_bytes).hexdigest(),
            "signature_algorithm": "ed25519",
            "signature": "0" * 128,
        }
        # Fail closed on a malformed envelope BEFORE signing or transport.
        try:
            unsigned = canonical_unsigned_final_holdout_client_request_bytes(
                request)
        except Exception as exc:  # noqa: BLE001
            raise HoldoutClientError(
                "the client request envelope failed its closed law") from exc
        signature = self._signer(
            FINAL_HOLDOUT_CLIENT_REQUEST_DOMAIN_V1 + unsigned)
        _require(isinstance(signature, (bytes, bytearray))
                 and len(signature) == 64,
                 "the signer must return a raw 64-byte ed25519 signature")
        request["signature"] = bytes(signature).hex()
        try:
            validate_final_holdout_client_request_v1(request)
        except Exception as exc:  # noqa: BLE001
            raise HoldoutClientError(
                "the signed client request failed its closed law") from exc
        return request

    def _authority_key(self, key_id: Any, now: datetime) -> Mapping[str, Any]:
        entry = next((item for item in self._bundle["keys"]
                      if item["key_id"] == key_id), None)
        _require(entry is not None,
                 "the response names an unknown authority key")
        assert entry is not None
        _require(entry["status"] == "active",
                 "the response was signed by an inactive authority key")
        not_before = datetime.strptime(
            entry["not_before"], "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc)
        not_after = datetime.strptime(
            entry["not_after"], "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc)
        _require(not_before <= now < not_after,
                 "the authority key is outside its validity window")
        return entry

    @staticmethod
    def _verify_ed25519(public_key_hex: str, signature_hex: str,
                        message: bytes, label: str) -> None:
        try:
            key = Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(public_key_hex))
            key.verify(bytes.fromhex(signature_hex), message)
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise HoldoutClientError(
                f"the {label} signature failed verification") from exc

    def _verify_embedded_audit(self, audit: Mapping[str, Any],
                               now: datetime) -> dict[str, Any]:
        entry = self._authority_key(audit.get("authority_key_id"), now)
        _require(audit.get("authority_id") == self._authority_id,
                 "the embedded audit names a different authority")
        try:
            unsigned = canonical_unsigned_final_holdout_access_audit_bytes(
                audit)
        except Exception as exc:  # noqa: BLE001
            raise HoldoutClientError(
                "the embedded terminal audit failed its closed law") from exc
        self._verify_ed25519(
            entry["public_key_hex"], str(audit.get("signature")),
            FINAL_HOLDOUT_ACCESS_AUDIT_DOMAIN_V1 + unsigned, "terminal audit")
        return _fresh(dict(audit), "terminal audit")

    def _call(self, *, path: str, body: Mapping[str, Any],
              body_bytes: bytes) -> dict[str, Any]:
        now = self._trusted_now()
        request = self._signed_request(
            path=path, body_bytes=body_bytes, now=now)
        envelope = json.dumps(
            {"client_request": request, "body": dict(body)},
            sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False).encode("utf-8")
        response = self._transport(path, envelope)
        _require(isinstance(response, TransportResponse),
                 "the transport must return a TransportResponse")
        try:
            parsed = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise HoldoutClientError(
                "the authority response is not valid JSON") from exc
        # An unsigned sanitized transport body is never trusted as a result.
        if isinstance(parsed, Mapping) and set(parsed) == {"code"}:
            _fail(
                "the authority returned an unsigned transport failure",
                code=str(parsed["code"]), status_code=response.status)
        try:
            wrapper = validate_final_holdout_response_wrapper_v1(parsed)
        except Exception as exc:  # noqa: BLE001
            raise HoldoutClientError(
                "the authority response failed the closed wrapper law"
            ) from exc
        service_response = wrapper["service_response"]
        body_out = wrapper["body"]
        _require(
            response.headers.get("cache-control") == "no-store",
            "the authority response is missing its no-store cache directive",
        )
        _require(
            int(service_response["status_code"]) == int(response.status),
            "the signed status contradicts the transport status",
        )
        _require(
            service_response["request_id"] == request["request_id"]
            and service_response["request_nonce"] == request["nonce"],
            "the authority response does not echo this request identity",
        )
        _require(service_response["authority_id"] == self._authority_id,
                 "the response names a different authority")
        entry = self._authority_key(service_response["authority_key_id"], now)
        if self._max_skew is not None:
            stamped = datetime.strptime(
                service_response["timestamp"], "%Y-%m-%dT%H:%M:%SZ").replace(
                    tzinfo=timezone.utc)
            _require(
                abs((stamped - now).total_seconds()) <= self._max_skew,
                "the authority response timestamp exceeds the accepted skew",
            )
        self._verify_ed25519(
            entry["public_key_hex"], service_response["signature"],
            FINAL_HOLDOUT_SERVICE_RESPONSE_DOMAIN_V1
            + canonical_unsigned_final_holdout_service_response_bytes(
                service_response),
            "authority response")
        return {"status": int(response.status), "body": body_out, "now": now}

    def _result_body(self, call: Mapping[str, Any], expected_code: str,
                     ) -> dict[str, Any]:
        body = call["body"]
        code = body.get("code")
        if code == expected_code:
            return _fresh(dict(body), "authority response body")
        if code == "AUDIT_PENDING":
            raise HoldoutAuditPending(
                "the terminal access audit is not available yet",
                code=str(code), status_code=int(call["status"]))
        if "terminal_audit" in body:
            audit = self._verify_embedded_audit(
                body["terminal_audit"], call["now"])
            raise HoldoutLeaseDenied(
                "the authority durably denied this lease",
                code=str(code), status_code=int(call["status"]),
                terminal_audit=audit)
        _fail("the authority returned a signed failure",
              code=str(code), status_code=int(call["status"]))
        raise AssertionError  # unreachable

    # ------------------------------------------------------- public protocol

    def create_lease(self, **fields: Any) -> dict[str, Any]:
        body = {
            "body_version": FINAL_HOLDOUT_LEASE_REQUEST_BODY_VERSION_V1,
            "access_protocol": FINAL_HOLDOUT_ACCESS_PROTOCOL,
            "release_id": _RELEASE_ID,
            **{key: fields[key] for key in (
                "capsule_id", "capsule_payload_sha256", "anchor_id",
                "anchor_sha256", "tenant_id", "workspace_id", "run_id",
                "confirmed_spec_hash", "snapshot_sha256",
                "validation_plan_hash", "complete_validation_plan_sha256",
                "locked_rule_sha256", "base_costs_sha256")},
        }
        call = self._call(
            path=FINAL_HOLDOUT_LEASE_PATH_V1, body=body,
            body_bytes=canonical_final_holdout_lease_request_body_bytes(body))
        return self._result_body(call, "LEASE_ISSUED")

    def consume(self, *, lease_id: str, anchor_id: str, capsule_id: str,
                capsule_payload_sha256: str, run_id: str) -> dict[str, Any]:
        body = {
            "body_version": FINAL_HOLDOUT_CONSUME_REQUEST_BODY_VERSION_V1,
            "access_protocol": FINAL_HOLDOUT_ACCESS_PROTOCOL,
            "release_id": _RELEASE_ID,
            "lease_id": lease_id,
            "anchor_id": anchor_id,
            "capsule_id": capsule_id,
            "capsule_payload_sha256": capsule_payload_sha256,
            "run_id": run_id,
        }
        call = self._call(
            path=FINAL_HOLDOUT_CONSUME_PATH_TEMPLATE_V1.format(
                lease_id=lease_id),
            body=body,
            body_bytes=canonical_final_holdout_consume_request_body_bytes(
                body))
        return self._result_body(call, "PLAINTEXT_RELEASED")

    def complete(self, *, lease_id: str, anchor_id: str, capsule_id: str,
                 run_id: str, outcome: str) -> dict[str, Any]:
        _require(outcome in _COMPLETION_OUTCOMES,
                 "the completion outcome is outside the closed vocabulary")
        body = {
            "body_version": FINAL_HOLDOUT_COMPLETION_REQUEST_BODY_VERSION_V1,
            "access_protocol": FINAL_HOLDOUT_ACCESS_PROTOCOL,
            "release_id": _RELEASE_ID,
            "lease_id": lease_id,
            "anchor_id": anchor_id,
            "capsule_id": capsule_id,
            "run_id": run_id,
            "outcome": outcome,
        }
        call = self._call(
            path=FINAL_HOLDOUT_COMPLETE_PATH_TEMPLATE_V1.format(
                lease_id=lease_id),
            body=body,
            body_bytes=canonical_final_holdout_completion_request_body_bytes(
                body))
        result = self._result_body(call, "EVALUATION_COMPLETED")
        result["terminal_audit"] = self._verify_embedded_audit(
            result["terminal_audit"], call["now"])
        return result

    def retrieve_audit(self, *, lease_id: str, anchor_id: str,
                       capsule_id: str, run_id: str) -> dict[str, Any]:
        body = {
            "body_version": FINAL_HOLDOUT_AUDIT_RETRIEVAL_BODY_VERSION_V1,
            "access_protocol": FINAL_HOLDOUT_ACCESS_PROTOCOL,
            "release_id": _RELEASE_ID,
            "lease_id": lease_id,
            "anchor_id": anchor_id,
            "capsule_id": capsule_id,
            "run_id": run_id,
        }
        call = self._call(
            path=FINAL_HOLDOUT_AUDIT_RETRIEVE_PATH_TEMPLATE_V1.format(
                lease_id=lease_id),
            body=body,
            body_bytes=canonical_final_holdout_audit_retrieval_body_bytes(
                body))
        result = self._result_body(call, "TERMINAL_AUDIT_RETURNED")
        result["terminal_audit"] = self._verify_embedded_audit(
            result["terminal_audit"], call["now"])
        return result

    def run_final_holdout_access_v1(
        self, *, evaluate: Callable[[Mapping[str, Any]], tuple[str, Any]],
        **lease_fields: Any,
    ) -> dict[str, Any]:
        """Drive one complete access: lease, consume, evaluate, complete, audit.

        The released plaintext exists only inside the ``evaluate`` call; the
        returned consume receipt has both observation subtrees removed, so no
        caller of this driver can persist plaintext by accident.  An evaluator
        exception reports an explicit failure to the authority before it is
        re-raised, so a crashed evaluation still produces a terminal audit.
        """
        _require(callable(evaluate), "evaluate must be callable")
        lease = self.create_lease(**lease_fields)
        lease_id = lease["lease_id"]
        identifiers = {
            "lease_id": lease_id,
            "anchor_id": lease["anchor_id"],
            "capsule_id": lease["capsule_id"],
            "run_id": lease["run_id"],
        }
        consume_body = self.consume(
            capsule_payload_sha256=lease["capsule_payload_sha256"],
            **identifiers)
        try:
            outcome, evaluation = evaluate(consume_body)
        except BaseException:
            self.complete(outcome="evaluation_failed", **identifiers)
            raise
        _require(outcome in _COMPLETION_OUTCOMES,
                 "the evaluator returned an outcome outside the closed "
                 "vocabulary")
        completion = self.complete(outcome=outcome, **identifiers)
        retrieved = self.retrieve_audit(**identifiers)
        receipt = {key: value for key, value in consume_body.items()
                   if key not in ("primary_observations",
                                  "benchmark_observations")}
        return {
            "lease": lease,
            "consume_receipt": receipt,
            "completion": completion,
            "terminal_audit": retrieved["terminal_audit"],
            "evaluation": evaluation,
        }


__all__ = [
    "FinalHoldoutClientV1",
    "HoldoutAuditPending",
    "HoldoutClientError",
    "HoldoutLeaseDenied",
    "TransportResponse",
    "loopback_urllib_transport_v1",
]
