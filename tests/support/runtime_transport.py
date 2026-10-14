"""Owned synthetic HTTP authority and typed installed-fixture acquisition.

This module never discovers devices. The CI driver supplies a NEW installed
fixture target. Credentials and HTTP bodies remain in memory; persisted
observations contain only digests, sizes and bounded states.
"""

from __future__ import annotations

import copy
import json
import os
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Protocol
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from mobile_audit.core import canonical_json, digest
from mobile_audit.runtime_acquisition import (
    AcquiredCapture,
    AcquisitionSession,
    BackendProbe,
    CaptureRequest,
    RawObservation,
    SurfaceCapture,
)

MAX_RESPONSE = 1024 * 1024
MAX_HEALTH_RESPONSE = 4096


class NoHealthRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class OwnedAuthority:
    """One new session, app and authority; no caller-reported replay outcome."""

    def __init__(self, package: str, build: str, *, invalidate: bool):
        self.package, self.build = package, build
        self.invalidate = invalidate
        self.identity = secrets.token_hex(32)
        self.session = ""
        self.credential = ""
        self.active = False
        self.logged_out = False
        # Keep A's original credential for independent before/after replay.
        # B is issued only by an authorized app HTTP switch, never the driver.
        self.switched = False
        self.b_credential = ""
        self.b_active = False
        self.b_authentication_nonces: set[str] = set()
        self.events: list[dict] = []
        self.lock = threading.Lock()

    def bind(self, session: str) -> None:
        if self.session or len(session) != 64 or any(c not in "0123456789abcdef" for c in session):
            raise ValueError("Authority session binding invalid")
        self.session = session

    def handle(self, route: str, authorization: str, raw: bytes) -> tuple[int, bytes]:
        with self.lock:
            try:
                body = json.loads(raw)
                bound = (
                    isinstance(body, dict)
                    and bool(self.session)
                    and body.get("session") == self.session
                    and body.get("package") == self.package
                    and body.get("build") == self.build
                )
            except (ValueError, TypeError):
                body, bound = {}, False
            if not isinstance(body, dict):
                body = {}
            token = authorization.removeprefix("Bearer ") if authorization.startswith("Bearer ") else ""
            authorized = bool(token) and secrets.compare_digest(token, self.credential)
            authorized_b = (
                bool(token) and bool(self.b_credential) and secrets.compare_digest(token, self.b_credential)
            )
            authenticated_account = "a" if authorized else "b" if authorized_b else None
            status, output = 403, {"outcome": "rejected"}
            issued = None
            if bound and route == "/issue" and not self.credential:
                self.credential = secrets.token_hex(32)
                self.active = True
                status, output = 200, {"credential": self.credential}
            elif bound and route == "/logout" and authorized and self.active and not self.logged_out:
                self.logged_out = True
                if self.invalidate:
                    self.active = False
                status, output = 200, {"outcome": "logout-observed"}
            elif (
                bound
                and route == "/switch"
                and authorized
                and self.active
                and not self.logged_out
                and not self.switched
                and set(body) == {"session", "package", "build", "to_account"}
                and body["to_account"] == "b"
            ):
                credential = secrets.token_hex(32)
                if secrets.compare_digest(credential, self.credential):
                    raise ValueError("Authority switch credential must differ")
                self.b_credential, self.b_active = credential, True
                self.switched, self.active = True, False
                issued = digest(credential.encode())
                status, output = 200, {"credential": credential, "account": "b"}
            elif bound and route == "/protected" and (authorized or authorized_b):
                nonce = body.get("nonce", "")
                if (
                    isinstance(nonce, str)
                    and len(nonce) == 64
                    and all(c in "0123456789abcdef" for c in nonce)
                ):
                    active = self.active if authorized else self.b_active
                    if authorized_b and (
                        set(body) != {"session", "package", "build", "account", "nonce"}
                        or body.get("account") != "b"
                        or nonce == self.session
                        or digest(nonce.encode()) in self.b_authentication_nonces
                    ):
                        active = False
                    status = 200 if active else 401
                    output = {"outcome": "accepted" if active else "rejected", "nonce": nonce}
                    if authorized_b:
                        output["account"] = "b"
                        if active:
                            self.b_authentication_nonces.add(digest(nonce.encode()))
            response = canonical_json(output).encode()
            self.events.append(
                {
                    "route": route
                    if route in {"/issue", "/logout", "/switch", "/protected"}
                    else "unsupported",
                    "status": status,
                    "bound": bound,
                    "session_sha256": digest(self.session.encode()),
                    "credential_sha256": digest(token.encode())
                    if authorized or authorized_b
                    else digest(self.credential.encode())
                    if route == "/issue" and status == 200
                    else None,
                    "authenticated_account": authenticated_account,
                    "issued_credential_sha256": issued,
                    "nonce_sha256": digest(body["nonce"].encode())
                    if isinstance(body.get("nonce"), str)
                    else None,
                    "request_sha256": digest(raw),
                    "response_sha256": digest(response),
                    "request_bytes": len(raw),
                    "response_bytes": len(response),
                }
            )
            return status, response


class AuthorityServer:
    """Actual HTTP listener, used only by the disposable hosted CI driver."""

    def __init__(self, authority: OwnedAuthority):
        self.authority = authority
        self.pid_sha256 = digest(str(os.getpid()).encode())
        self.instance_sha256 = digest(authority.identity.encode())
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args):
                pass  # Never retain HTTP headers, bodies, credentials or raw service logs.

            def do_POST(self):
                length = self.headers.get("Content-Length", "")
                if not length.isdigit() or int(length) > 4096:
                    self.send_error(413)
                    return
                raw = self.rfile.read(int(length))
                if self.path == "/health":
                    status, response = owner.health_response(raw)
                else:
                    status, response = authority.handle(self.path, self.headers.get("Authorization", ""), raw)
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.server.timeout = 1
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]
        self.endpoint = f"http://127.0.0.1:{self.port}"

    def health_response(self, raw: bytes) -> tuple[int, bytes]:
        """A nonce echo never creates a credential, session or authority event."""
        nonce = None
        try:
            body = json.loads(raw)
            nonce = body.get("nonce") if isinstance(body, dict) else None
            valid = (
                isinstance(body, dict)
                and set(body) == {"nonce"}
                and isinstance(nonce, str)
                and len(nonce) == 64
                and all(char in "0123456789abcdef" for char in nonce)
            )
        except (ValueError, TypeError):
            valid = False
        if not valid:
            return 400, b'{"state":"rejected"}'
        return 200, canonical_json(
            {
                "state": "ready",
                "nonce": nonce,
                "pid_sha256": self.pid_sha256,
                "instance_sha256": self.instance_sha256,
            }
        ).encode()

    def health(self) -> dict:
        """One bounded, proxy-free probe of this newly owned loopback listener."""
        nonce = secrets.token_hex(32)
        result = {
            "state": "unconfirmed",
            "nonce_sha256": digest(nonce.encode()),
            "pid_sha256": self.pid_sha256,
            "instance_sha256": self.instance_sha256,
        }
        try:
            request = Request(
                self.endpoint + "/health",
                data=canonical_json({"nonce": nonce}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with build_opener(ProxyHandler({}), NoHealthRedirect()).open(request, timeout=2) as response:
                raw = response.read(MAX_HEALTH_RESPONSE + 1)
                if len(raw) > MAX_HEALTH_RESPONSE or response.status != 200:
                    return result
            value = json.loads(raw)
            if value != {
                "state": "ready",
                "nonce": nonce,
                "pid_sha256": self.pid_sha256,
                "instance_sha256": self.instance_sha256,
            }:
                return result
            return {**result, "state": "verified", "response_sha256": digest(raw), "response_bytes": len(raw)}
        except (OSError, ValueError, TypeError):
            return result

    def event_counts(self) -> dict:
        with self.authority.lock:
            return {
                route: sum(event["route"] == route for event in self.authority.events)
                for route in ("/issue", "/logout", "/switch", "/protected", "unsupported")
            }

    def replay(self, nonce: str) -> BackendProbe:
        authority = self.authority
        if not authority.credential:
            raise ValueError("No credential issued by app HTTP request")
        body = canonical_json(
            {
                "session": authority.session,
                "package": authority.package,
                "build": authority.build,
                "nonce": nonce,
            }
        ).encode()
        headers = {"Authorization": "Bearer " + authority.credential, "Content-Type": "application/json"}
        request = Request(self.endpoint + "/protected", data=body, headers=headers, method="POST")
        # Bypass environment HTTP proxies only for this newly owned loopback authority.
        opener = build_opener(ProxyHandler({}))
        try:
            with opener.open(request, timeout=10) as response:
                status, raw = response.status, response.read(MAX_RESPONSE + 1)
        except HTTPError as response:
            try:
                status, raw = response.code, response.read(MAX_RESPONSE + 1)
            finally:
                response.close()
        if len(raw) > MAX_RESPONSE:
            raise ValueError("Owned authority response exceeds bound")
        output = json.loads(raw)
        if output.get("nonce") != nonce or (status, output.get("outcome")) not in {
            (200, "accepted"),
            (401, "rejected"),
        }:
            raise ValueError("Owned authority replay challenge/status differs")
        return BackendProbe(
            digest(authority.identity.encode()),
            digest(authority.credential.encode()),
            output["outcome"],
            canonical_json(
                {
                    "method": "POST",
                    "url": self.endpoint + "/protected",
                    "headers": headers,
                    "body": body.decode(),
                }
            ).encode(),
            canonical_json({"status": status, "body": output}).encode(),
        )

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class InstalledTarget(Protocol):
    platform: str
    package: str
    build: dict[str, str]

    def installed_build(self) -> dict[str, str]: ...

    def deliver(self, url: str, expected: dict) -> dict: ...


class InstalledTransportAdapter:
    """NEW installed app data only; every response binds the OS-delivered challenge."""

    def __init__(
        self,
        target: InstalledTarget,
        server: AuthorityServer,
        *,
        retain: bool,
        transition_kind: str = "logout",
    ):
        if transition_kind not in {"logout", "account_switch"}:
            raise ValueError("Installed fixture transition kind unsupported")
        self.target, self.server, self.retain = target, server, retain
        self.transition_kind = transition_kind
        self.account_b_authentication: dict | None = None
        self.capture_nonces: set[str] = set()
        self.session: AcquisitionSession | None = None
        # Recorder failures remain inconclusive; the dedicated CI driver may
        # project this exception into its fixed, redacted failure taxonomy.
        self.acquisition_error: Exception | None = None
        self.after = False
        self.delivery_transport = (
            "android-os-intent" if target.platform == "android" else "ios-os-url-context"
        )

    def _exchange(self, fields: dict[str, str]) -> dict:
        self.acquisition_error = None
        try:
            response = self.target.deliver("apsatransport://fixture?" + urlencode(fields), fields)
        except (ValueError, OSError) as error:
            self.acquisition_error = error
            raise
        if (
            not isinstance(response, dict)
            or response.get("package") != self.target.package
            or response.get("session") != fields["session"]
            or response.get("action") != fields["action"]
            or response.get("delivery_transport") != self.delivery_transport
            or any(response.get(key) != value for key, value in self.target.build.items())
            or self.target.installed_build() != self.target.build
        ):
            self.acquisition_error = ValueError("Installed fixture target/build/transport response differs")
            raise self.acquisition_error
        return response

    def start_session(self, binding: dict, nonce: str) -> AcquisitionSession:
        if (
            self.session
            or binding["platform"] != self.target.platform
            or binding["package"] != self.target.package
            or binding["build"] != self.target.build
        ):
            raise ValueError("Installed fixture session binding differs")
        self.server.authority.bind(nonce)
        endpoint = (
            self.server.endpoint if self.target.platform == "ios" else f"http://10.0.2.2:{self.server.port}"
        )
        response = self._exchange(
            {"action": "session", "session": nonce, "backend": endpoint, "retain": str(self.retain).lower()}
        )
        if (
            response.get("fresh_store") is not True
            or response.get("account") != "a"
            or response.get("state") != "authenticated"
            or not self.server.authority.credential
        ):
            raise ValueError("Installed fixture HTTP/session initialization differs")
        self.session = AcquisitionSession(
            "installed-ci-transport",
            "instrumented",
            nonce,
            self.target.platform,
            self.target.package,
            copy.deepcopy(self.target.build),
        )
        return self.session

    def open_url(self, url: str) -> dict:
        if url != "synthetic://transition" or self.after or not self.session:
            raise ValueError("Installed fixture transition unsupported")
        response = self._exchange(
            {"action": "transition", "session": self.session.nonce, "kind": self.transition_kind}
        )
        if self.transition_kind == "logout":
            if (
                response.get("kind") != "logout"
                or response.get("account") != ""
                or response.get("state") != "logged_out"
                or response.get("delivery") != "target-observed"
                or not self.server.authority.logged_out
                or self.server.authority.switched
            ):
                raise ValueError("Installed fixture logout delivery/HTTP authority differs")
        else:
            authority = self.server.authority
            if (
                response.get("kind") != "account_switch"
                or response.get("account") != "b"
                or response.get("state") != "authenticated"
                or response.get("delivery") != "target-observed"
                or not authority.switched
                or not authority.b_active
                or authority.active
                or authority.logged_out
            ):
                raise ValueError("Installed fixture switch delivery/HTTP authority differs")
            self.account_b_authentication = self._verified_b_authentication(response)
        self.after = True
        return {"delivery": "target-activity-reported", "transport": self.delivery_transport}

    def _verified_b_authentication(self, response: dict, nonce: str | None = None) -> dict:
        proof = response.get("account_authentication")
        authority = self.server.authority
        if (
            not isinstance(proof, dict)
            or set(proof) != {"account", "credential_sha256", "nonce_sha256"}
            or proof.get("account") != "b"
            or not authority.b_credential
            or proof.get("credential_sha256") != digest(authority.b_credential.encode())
            or not isinstance(proof.get("nonce_sha256"), str)
            or len(proof["nonce_sha256"]) != 64
            or any(char not in "0123456789abcdef" for char in proof["nonce_sha256"])
            or proof.get("nonce_sha256") not in authority.b_authentication_nonces
            or proof["nonce_sha256"] == digest(authority.session.encode())
            or proof["nonce_sha256"] in {digest(value.encode()) for value in self.capture_nonces}
            or (nonce is not None and proof["nonce_sha256"] != digest(nonce.encode()))
            or not any(
                event["route"] == "/protected"
                and event["status"] == 200
                and event["bound"]
                and event["authenticated_account"] == "b"
                and event["credential_sha256"] == proof["credential_sha256"]
                and event["nonce_sha256"] == proof["nonce_sha256"]
                for event in authority.events
            )
        ):
            raise ValueError("Installed fixture account B authentication differs")
        return proof.copy()

    def capture(self, request: CaptureRequest) -> AcquiredCapture:
        if request.session != self.session:
            raise ValueError("Installed fixture capture session differs")
        if (
            not isinstance(request.nonce, str)
            or len(request.nonce) != 64
            or any(char not in "0123456789abcdef" for char in request.nonce)
            or request.nonce == request.session.nonce
            or request.nonce in self.capture_nonces
        ):
            raise ValueError("Installed fixture capture nonce differs")
        expected_account = (
            "b" if self.after and self.transition_kind == "account_switch" else None if self.after else "a"
        )
        if (
            request.account != expected_account
            or request.state != ("logged_out" if expected_account is None else "authenticated")
            or request.transition != (self.transition_kind if self.after else None)
        ):
            raise ValueError("Installed fixture capture transition kind differs")
        response = self._exchange(
            {
                "action": "capture",
                "session": request.session.nonce,
                "nonce": request.nonce,
                "snapshot": request.snapshot,
                "account": request.account or "",
                "state": request.state,
                "transition": request.transition or "",
            }
        )
        delivery = "target-observed" if self.after else "baseline"
        if (
            response.get("nonce") != request.nonce
            or response.get("snapshot") != request.snapshot
            or response.get("account") != (request.account or "")
            or response.get("state") != request.state
            or response.get("transition") != (request.transition or "")
            or response.get("delivery") != delivery
            or response.get("completeness") != "complete"
            or not isinstance(response.get("storage"), str)
            or len(response["storage"].encode()) > MAX_RESPONSE
        ):
            raise ValueError("Installed fixture capture challenge/state differs")
        if self.after and self.transition_kind == "account_switch":
            self._verified_b_authentication(response, request.nonce)
        self.capture_nonces.add(request.nonce)
        probe = self.server.replay(request.nonce)
        return AcquiredCapture(
            request,
            request.account,
            request.state,
            delivery,
            (
                SurfaceCapture(
                    "storage",
                    "complete",
                    (RawObservation("new-fixture-state", response["storage"].encode()),),
                ),
                SurfaceCapture(
                    "network", "complete", (RawObservation("owned-http-protected-response", probe.response),)
                ),
                SurfaceCapture("ui", "unsupported", ()),
                SurfaceCapture("logs", "unsupported", ()),
            ),
            probe,
        )
